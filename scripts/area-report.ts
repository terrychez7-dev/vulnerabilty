// 영역 분류 점검용: KEV 카탈로그를 받아 lib/areas.ts 규칙으로 분류한 결과를 보여줍니다.
// DB 없이 실행됩니다. 미분류(app) 비율과 자주 나오는 미분류 벤더·제품을 보고 규칙을 보완하세요.
// 실행: npm run area-report [-- 90]   (기본: 최근 90일 기준 비율도 함께 출력)
import { AREAS } from "../lib/areas";
import { fetchKev, toRow } from "../lib/kev";

const TARGET = 0.15; // 성공 지표: 최근 90일 미분류 15% 이하

async function main() {
  const days = Number(process.argv[2]) || 90;
  const { catalog, source } = await fetchKev();
  const rows = catalog.vulnerabilities.map(toRow);
  const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
  const recent = rows.filter((r) => r.date_added >= since);
  console.log(`KEV ${catalog.catalogVersion} (${rows.length}건) from ${source}\n`);

  const pct = (n: number, d: number) => (d ? ((n / d) * 100).toFixed(1) : "0.0") + "%";
  console.log(`${"영역".padEnd(16)}${"전체".padStart(8)}${`최근 ${days}일`.padStart(12)}`);
  for (const a of AREAS) {
    const all = rows.filter((r) => r.area === a.key).length;
    const rec = recent.filter((r) => r.area === a.key).length;
    console.log(`${a.name.padEnd(16)}${String(all).padStart(8)}${String(rec).padStart(12)}`);
  }

  const appAll = rows.filter((r) => r.area === "app").length;
  const appRecent = recent.filter((r) => r.area === "app").length;
  const ratio = recent.length ? appRecent / recent.length : 0;
  console.log(`\n미분류: 전체 ${appAll}/${rows.length} (${pct(appAll, rows.length)}), 최근 ${days}일 ${appRecent}/${recent.length} (${pct(appRecent, recent.length)})`);
  console.log(ratio <= TARGET ? `목표(${TARGET * 100}% 이하) 충족` : `목표(${TARGET * 100}% 이하) 미달: 아래 항목을 lib/areas.ts 규칙에 반영하세요.`);

  const top = new Map<string, number>();
  for (const r of rows.filter((r) => r.area === "app")) {
    const k = `${r.vendor} / ${r.product}`;
    top.set(k, (top.get(k) ?? 0) + 1);
  }
  console.log("\n미분류 상위 벤더/제품 (전체 기간):");
  for (const [k, n] of [...top.entries()].sort((a, b) => b[1] - a[1]).slice(0, 25)) {
    console.log(`  ${String(n).padStart(3)}  ${k}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
