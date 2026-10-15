import { adminClient, selectAll } from "./supabase";
import { fetchKev, toRow, type KevRow } from "./kev";
import { enrichCve, type Enrichment } from "./cve";
import { summarizeKo, type SummaryInput } from "./summarize";

export type SyncOptions = {
  trigger: string;
  budgetMs: number; // 이 시간 안에서 처리하고, 남은 건 다음 실행으로 넘깁니다.
  enrichLimit?: number;
  summaryLimit?: number;
  log?: (msg: string) => void;
};

export type SyncResult = {
  runId: number | null;
  catalogVersion: string;
  kevTotal: number;
  kevNew: number;
  kevChanged: number;
  enriched: number;
  enrichErrors: number;
  summarized: number;
  summaryErrors: number;
  pendingEnrich: number;
  pendingSummary: number;
  durationMs: number;
  status: "ok" | "partial";
};

const DAY = 86_400_000;
const isoDaysAgo = (days: number) => new Date(Date.now() - days * DAY).toISOString().slice(0, 10);
const numEnv = (name: string, def: number) => {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : def;
};

async function pool<T>(items: T[], size: number, keepGoing: () => boolean, fn: (item: T) => Promise<void>) {
  let i = 0;
  const worker = async () => {
    while (i < items.length && keepGoing()) {
      const item = items[i++];
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
}

type KevLite = { cve_id: string; kev_hash: string; date_added: string; updated_at: string };
type EnrichLite = { cve_id: string; status: string; fetched_at: string; cve_updated: string | null };

export async function runSync(opts: SyncOptions): Promise<SyncResult> {
  const t0 = Date.now();
  const log = opts.log ?? (() => {});
  const left = () => opts.budgetMs - (Date.now() - t0);
  const db = adminClient();

  const { data: run } = await db.from("sync_runs").insert({ trigger: opts.trigger }).select("id").single();
  const runId = (run?.id as number | undefined) ?? null;

  try {
    // 1) KEV 전체 수집 → 신규·변경분만 upsert
    const { catalog, source } = await fetchKev();
    log(`KEV ${catalog.catalogVersion} (${catalog.vulnerabilities.length}건) from ${source}`);
    const rows: KevRow[] = catalog.vulnerabilities.map(toRow);
    const existing = await selectAll<{ cve_id: string; kev_hash: string; area: string }>(db, "kev_vulns", "cve_id,kev_hash,area");
    const known = new Map(existing.map((r) => [r.cve_id, r]));
    // 원본이 바뀐 건(신규 포함)은 updated_at을 갱신해 보강·요약을 다시 하게 하고,
    // 분류 규칙만 바뀐 건은 area만 고칩니다.
    const changed = rows.filter((r) => known.get(r.cve_id)?.kev_hash !== r.kev_hash);
    const reclassified = rows.filter((r) => {
      const k = known.get(r.cve_id);
      return k && k.kev_hash === r.kev_hash && k.area !== r.area;
    });
    const kevNew = changed.filter((r) => !known.has(r.cve_id)).length;
    const now = new Date().toISOString();
    for (let i = 0; i < changed.length; i += 500) {
      const chunk = changed.slice(i, i + 500).map((r) => ({ ...r, updated_at: now }));
      const { error } = await db.from("kev_vulns").upsert(chunk, { onConflict: "cve_id" });
      if (error) throw new Error(`kev_vulns 저장 실패: ${error.message}`);
    }
    for (let i = 0; i < reclassified.length; i += 500) {
      const chunk = reclassified.slice(i, i + 500); // updated_at은 그대로 둡니다.
      const { error } = await db.from("kev_vulns").upsert(chunk, { onConflict: "cve_id" });
      if (error) throw new Error(`kev_vulns 재분류 저장 실패: ${error.message}`);
    }
    log(`KEV 신규 ${kevNew}건, 변경 ${changed.length - kevNew}건, 재분류 ${reclassified.length}건`);

    // 2) CVE 공식 레코드 보강 (ENRICH_DAYS 이내 항목)
    const enrichSince = isoDaysAgo(numEnv("ENRICH_DAYS", 365));
    const kevAll = await selectAll<KevLite>(db, "kev_vulns", "cve_id,kev_hash,date_added,updated_at");
    const enrichAll = await selectAll<EnrichLite>(db, "cve_enrichment", "cve_id,status,fetched_at,cve_updated");
    const enrichMap = new Map(enrichAll.map((e) => [e.cve_id, e]));
    const recent30 = isoDaysAgo(30);
    const age = (ts: string) => Date.now() - Date.parse(ts);
    const pendingEnrich = kevAll
      .filter((k) => k.date_added >= enrichSince)
      .filter((k) => {
        const e = enrichMap.get(k.cve_id);
        if (!e) return true;
        if (Date.parse(e.fetched_at) < Date.parse(k.updated_at)) return true; // KEV 항목이 바뀜
        if (e.status === "error") return age(e.fetched_at) > 6 * 3_600_000;
        if (e.status === "not_found") return age(e.fetched_at) > 3 * DAY; // 레코드 공개 지연
        return k.date_added >= recent30 && age(e.fetched_at) > 7 * DAY; // 최근 항목은 CVSS 추가 반영
      })
      .sort((a, b) => b.date_added.localeCompare(a.date_added))
      .slice(0, opts.enrichLimit ?? 200);

    let enriched = 0;
    const enrichBudget = () => left() > opts.budgetMs * 0.45;
    const results: Enrichment[] = [];
    await pool(pendingEnrich, 6, enrichBudget, async (k) => {
      results.push(await enrichCve(k.cve_id));
    });
    for (let i = 0; i < results.length; i += 200) {
      const { error } = await db.from("cve_enrichment").upsert(results.slice(i, i + 200), { onConflict: "cve_id" });
      if (error) throw new Error(`cve_enrichment 저장 실패: ${error.message}`);
    }
    enriched = results.length;
    const enrichErrors = results.filter((r) => r.status === "error").length;
    for (const r of results) enrichMap.set(r.cve_id, r);
    log(`CVE 보강 ${enriched}건 (오류 ${enrichErrors}건, 대기 ${pendingEnrich.length - enriched}건)`);

    // 3) Claude 한국어 요약 (SUMMARY_DAYS 이내, 보강이 끝난 항목)
    let summarized = 0;
    let summaryErrors = 0;
    let pendingSummaryCount = 0;
    if (process.env.ANTHROPIC_API_KEY) {
      const summarySince = isoDaysAgo(numEnv("SUMMARY_DAYS", 180));
      const summaries = await selectAll<{ cve_id: string; source_stamp: string }>(db, "cve_summaries_ko", "cve_id,source_stamp");
      const stampMap = new Map(summaries.map((s) => [s.cve_id, s.source_stamp]));
      const stampOf = (k: KevLite) => `${k.kev_hash}:${enrichMap.get(k.cve_id)?.cve_updated ?? ""}`;
      const pending = kevAll
        .filter((k) => k.date_added >= summarySince && enrichMap.has(k.cve_id) && enrichMap.get(k.cve_id)!.status !== "error")
        .filter((k) => stampMap.get(k.cve_id) !== stampOf(k))
        .sort((a, b) => b.date_added.localeCompare(a.date_added));
      pendingSummaryCount = pending.length;
      const batch = pending.slice(0, opts.summaryLimit ?? 40);
      const ids = batch.map((k) => k.cve_id);
      const detail = new Map<string, Record<string, unknown>>();
      for (let i = 0; i < ids.length; i += 100) {
        const { data, error } = await db
          .from("kev_dashboard_v")
          .select("cve_id,vendor,product,vuln_name,short_description,required_action,due_date,ransomware,cwes,notes,cve_title,cvss_score,cvss_vector,affected,fixed")
          .in("cve_id", ids.slice(i, i + 100));
        if (error) throw new Error(`요약 대상 조회 실패: ${error.message}`);
        for (const d of data ?? []) detail.set(d.cve_id as string, d);
      }
      const { data: descRows } = await db.from("cve_enrichment").select("cve_id,description").in("cve_id", ids);
      const descMap = new Map((descRows ?? []).map((d) => [d.cve_id as string, d.description as string | null]));

      await pool(batch, 3, () => left() > 25_000, async (k) => {
        const d = detail.get(k.cve_id);
        if (!d) return;
        const input = { ...d, cve_description: descMap.get(k.cve_id) ?? null } as unknown as SummaryInput;
        try {
          const s = await summarizeKo(input);
          const { error } = await db.from("cve_summaries_ko").upsert(
            { cve_id: k.cve_id, ...s, source_stamp: stampOf(k), generated_at: new Date().toISOString() },
            { onConflict: "cve_id" },
          );
          if (error) throw new Error(error.message);
          summarized++;
        } catch (e) {
          summaryErrors++;
          log(`요약 실패 ${k.cve_id}: ${(e as Error).message}`);
        }
      });
      log(`한국어 요약 ${summarized}건 (실패 ${summaryErrors}건, 대기 ${pendingSummaryCount - summarized}건)`);
    }

    const result: SyncResult = {
      runId,
      catalogVersion: catalog.catalogVersion,
      kevTotal: rows.length,
      kevNew,
      kevChanged: changed.length - kevNew,
      enriched,
      enrichErrors,
      summarized,
      summaryErrors,
      pendingEnrich: Math.max(0, pendingEnrich.length - enriched),
      pendingSummary: Math.max(0, pendingSummaryCount - summarized),
      durationMs: Date.now() - t0,
      status: "ok",
    };
    result.status = result.pendingEnrich + result.pendingSummary + summaryErrors > 0 ? "partial" : "ok";
    const notes = [
      enrichErrors ? `CVE 보강 오류 ${enrichErrors}건` : "",
      summaryErrors ? `요약 실패 ${summaryErrors}건` : "",
      process.env.ANTHROPIC_API_KEY ? "" : "ANTHROPIC_API_KEY 없음: 요약 생략",
    ].filter(Boolean);

    if (runId) {
      await db.from("sync_runs").update({
        finished_at: new Date().toISOString(),
        catalog_version: result.catalogVersion,
        kev_source: source,
        kev_total: result.kevTotal,
        kev_new: result.kevNew,
        kev_changed: result.kevChanged,
        enriched: result.enriched,
        enrich_errors: result.enrichErrors,
        summarized: result.summarized,
        summary_errors: result.summaryErrors,
        pending_enrich: result.pendingEnrich,
        pending_summary: result.pendingSummary,
        status: result.status,
        error: notes.length ? notes.join(", ") : null,
      }).eq("id", runId);
    }
    return result;
  } catch (e) {
    if (runId) {
      await db.from("sync_runs").update({
        finished_at: new Date().toISOString(),
        status: "error",
        error: (e as Error).message.slice(0, 300),
      }).eq("id", runId);
    }
    throw e;
  }
}
