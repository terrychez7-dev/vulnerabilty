import { fetchJson } from "./kev";

// CVE 공식 레코드: CVEProject/cvelistV5 (GitHub raw)
export function cveRecordUrl(cveId: string): string {
  const [, year, num] = cveId.split("-");
  return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${Math.floor(Number(num) / 1000)}xxx/${cveId}.json`;
}

type Version = { version?: string; lessThan?: string; lessThanOrEqual?: string; status?: string; versionType?: string };
type Affected = { vendor?: string; product?: string; versions?: Version[] };
type Container = {
  title?: string;
  descriptions?: { lang?: string; value: string }[];
  metrics?: Record<string, { baseScore?: number; baseSeverity?: string; vectorString?: string }>[];
  affected?: Affected[];
};
type CveRecord = {
  cveMetadata?: { datePublished?: string; dateUpdated?: string };
  containers?: { cna?: Container; adp?: Container[] };
};

export type Enrichment = {
  cve_id: string;
  status: "ok" | "not_found" | "error";
  published: string | null;
  cve_updated: string | null;
  title: string | null;
  description: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  attack_vector: string | null;
  affected: string | null;
  fixed: string | null;
  error: string | null;
  fetched_at: string;
};

const DOTTED = /^\d+(\.\d+)+$/;

function pickCvss(rec: CveRecord) {
  const containers = [rec.containers?.cna ?? {}, ...(rec.containers?.adp ?? [])];
  for (const want of ["cvssV3_1", "cvssV3_0", "cvssV4_0"]) {
    for (const c of containers) {
      for (const m of c.metrics ?? []) {
        const x = m[want];
        if (x?.baseScore != null) {
          return { score: x.baseScore, severity: x.baseSeverity ?? null, vector: x.vectorString ?? null, version: want };
        }
      }
    }
  }
  return null;
}

export function attackVector(vector: string | null | undefined): string | null {
  if (!vector) return null;
  if (/AV:N/.test(vector)) return "네트워크";
  if (/AV:A/.test(vector)) return "인접 네트워크";
  if (/AV:L/.test(vector)) return "로컬";
  if (/AV:P/.test(vector)) return "물리";
  return null;
}

function summarizeAffected(rec: CveRecord, limit = 10): string {
  const out: string[] = [];
  for (const a of rec.containers?.cna?.affected ?? []) {
    const parts = [a.vendor, a.product].filter((p) => p && p !== "n/a") as string[];
    const name = parts.length === 2 && parts[0].toLowerCase() === parts[1].toLowerCase() ? parts[0] : parts.join(" ");
    if (name && !out.includes(name)) out.push(name);
  }
  const more = Math.max(0, out.length - limit);
  return out.slice(0, limit).join(", ") + (more ? ` 외 ${more}개` : "");
}

// 수정 버전 힌트: 리눅스형(unaffected 브랜치 버전)과 MS형(affected lessThan 빌드)을 모두 읽습니다.
function summarizeFixed(rec: CveRecord, limit = 24): string {
  const out: string[] = [];
  for (const a of rec.containers?.cna?.affected ?? []) {
    for (const v of a.versions ?? []) {
      const type = (v.versionType ?? "").toLowerCase();
      if (type === "git") continue;
      let label: string | null = null;
      if (v.status === "unaffected" && v.lessThanOrEqual && DOTTED.test(v.version ?? "")) label = v.version!;
      else if (v.status === "affected" && type !== "semver" && DOTTED.test(v.lessThan ?? "")) label = `${a.product} ${v.lessThan}`;
      if (label && !out.includes(label)) out.push(label);
    }
  }
  const more = Math.max(0, out.length - limit);
  return out.slice(0, limit).join(", ") + (more ? ` 외 ${more}개` : "");
}

export async function enrichCve(cveId: string): Promise<Enrichment> {
  const now = new Date().toISOString();
  const empty = {
    published: null, cve_updated: null, title: null, description: null, cvss_score: null, cvss_severity: null,
    cvss_vector: null, cvss_version: null, attack_vector: null, affected: null, fixed: null,
  };
  try {
    const rec = await fetchJson<CveRecord>(cveRecordUrl(cveId), 20_000);
    const cna = rec.containers?.cna ?? {};
    const desc = cna.descriptions?.find((d) => (d.lang ?? "").startsWith("en"))?.value ?? null;
    const cvss = pickCvss(rec);
    return {
      cve_id: cveId,
      status: "ok",
      published: rec.cveMetadata?.datePublished?.slice(0, 10) ?? null,
      cve_updated: rec.cveMetadata?.dateUpdated ?? null,
      title: cna.title ?? null,
      description: desc ? desc.slice(0, 4000) : null,
      cvss_score: cvss?.score ?? null,
      cvss_severity: cvss?.severity ?? null,
      cvss_vector: cvss?.vector ?? null,
      cvss_version: cvss?.version ?? null,
      attack_vector: attackVector(cvss?.vector),
      affected: summarizeAffected(rec) || null,
      fixed: summarizeFixed(rec) || null,
      error: null,
      fetched_at: now,
    };
  } catch (e) {
    const status = (e as { status?: number }).status === 404 ? "not_found" : "error";
    return { cve_id: cveId, status, ...empty, error: status === "error" ? (e as Error).message.slice(0, 300) : null, fetched_at: now };
  }
}
