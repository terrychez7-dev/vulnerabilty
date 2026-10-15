import { readClient } from "@/lib/supabase";
import { AREAS } from "@/lib/areas";
import Dashboard, { type Vuln, type SyncInfo } from "@/components/Dashboard";

export const dynamic = "force-dynamic";

const PERIODS = [30, 90, 180, 365];

type SP = Promise<Record<string, string | string[] | undefined>>;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

export default async function Page({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const days = PERIODS.includes(Number(one(sp.days))) ? Number(one(sp.days)) : 30;
  const areaParam = one(sp.area) ?? "server_os";
  const area = areaParam === "all" || AREAS.some((a) => a.key === areaParam) ? areaParam : "server_os";
  const cve = one(sp.cve) ?? null;

  const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
  const db = readClient();
  const [vulns, runs] = await Promise.all([
    db
      .from("kev_dashboard_v")
      .select(
        "cve_id,vendor,product,vuln_name,date_added,due_date,short_description,required_action,ransomware,forensic_triage,notes,cwes,area,cve_published,cve_title,cvss_score,cvss_severity,cvss_vector,attack_vector,affected,fixed,title_ko,summary_ko,scenario_ko,action_ko",
      )
      .gte("date_added", since)
      .order("date_added", { ascending: false })
      .limit(2000),
    db
      .from("sync_runs")
      .select("finished_at,catalog_version,status")
      .in("status", ["ok", "partial"])
      .order("started_at", { ascending: false })
      .limit(1),
  ]);

  if (vulns.error) {
    return (
      <main className="wrap">
        <h1>데이터를 불러오지 못했습니다</h1>
        <p className="mut">Supabase 연결 설정(SUPABASE_URL, SUPABASE_READ_KEY)과 스키마 적용 여부를 확인하세요.</p>
      </main>
    );
  }

  return (
    <Dashboard
      rows={(vulns.data ?? []) as Vuln[]}
      days={days}
      since={since}
      initialArea={area}
      initialCve={cve}
      periods={PERIODS}
      areas={AREAS.map(({ key, name }) => ({ key, name }))}
      sync={(runs.data?.[0] as SyncInfo | undefined) ?? null}
    />
  );
}
