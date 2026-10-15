// 최초 구축용: 로컬에서 실행 시간 제한 없이 KEV 저장 → CVE 보강 → 한국어 요약을 끝까지 채웁니다.
// 실행: npm run backfill   (.env.local 필요)
import { runSync } from "../lib/sync";

async function main() {
  for (let round = 1; round <= 50; round++) {
    const r = await runSync({
      trigger: "backfill",
      budgetMs: 15 * 60_000,
      enrichLimit: 500,
      summaryLimit: 60,
      log: (m) => console.log(`[${round}] ${m}`),
    });
    console.log(`[${round}] 남은 보강 ${r.pendingEnrich}건, 남은 요약 ${r.pendingSummary}건`);
    if (r.pendingEnrich === 0 && (r.pendingSummary === 0 || r.summarized === 0)) break;
  }
  console.log("완료");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
