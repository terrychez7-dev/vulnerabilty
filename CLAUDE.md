@AGENTS.md

# KEV 인프라 취약점 대시보드

CISA KEV(실제 악용 확인 취약점)를 수집해 인프라 영역별로 보여 주는 대시보드다. Next.js(Vercel) + Supabase + Claude API로 구성된다.

## 작업을 시작할 때 읽을 문서

- `PRD.md`: 요구사항 기준 문서. 요구사항 ID(F-SYNC, F-AREA, F-SUM, F-UI, N-)로 작업을 대조한다.
- `WORKLOG.md`: 지금까지 한 일과 결정, 검증 결과. 맨 아래 장이 가장 최근 작업이다.
- `todo.md`: 남은 할 일 체크리스트.

새 작업이 끝나면 `WORKLOG.md`에 날짜별 장을 추가하고, 완료된 항목은 `todo.md`에서 체크한다. 요구사항이나 상태 같은 사실이 바뀌었을 때만 `PRD.md`를 고친다.

## 운영 정보

- 운영 주소: https://vulnerabilty-z4ua.vercel.app/
- GitHub: https://github.com/terrychez7-dev/vulnerabilty (`main`에 push하면 Vercel이 자동 배포)
- Vercel Cron: `vercel.json`의 `0 23 * * *`(UTC) = 매일 08:00 KST. Hobby 플랜이라 08:00~08:59 사이에 실행된다. 대시보드에서는 편집할 수 없고 `vercel.json`으로만 바꾼다.
- 동기화 이력은 Supabase `sync_runs` 테이블에 있다. `trigger` 값은 `cron` / `manual` / `backfill`이다.

## 주요 파일

- `lib/sync.ts`: 동기화 흐름 (KEV 저장 → CVE 보강 → 한국어 요약)
- `lib/areas.ts`: 영역 분류 규칙. 점검은 `npm run area-report`로 한다.
- `lib/summarize.ts`: Claude 요약 프롬프트
- `components/Dashboard.tsx`: 화면
- `supabase/migrations/001_kev_schema.sql`: 스키마와 RLS

## 로컬 환경 주의

- 이 Mac의 시스템 Node는 v6이라 프로젝트를 실행할 수 없다(20.9 이상 필요). 검증할 때는 Node 22를 세션 임시 폴더에 받아 `PATH` 앞에 붙여 쓴다.
- 비밀값(Supabase secret 키, `CRON_SECRET`, `ANTHROPIC_API_KEY`)은 `.env.local`에만 둔다. 출력할 때는 앞 몇 글자만 보이게 가리고, 커밋하지 않는다.
- Supabase 앞단 WAF가 공격 코드가 든 CVE 원문을 막을 수 있다. `lib/sync.ts`에서 한 건씩 재시도하는 방식으로 처리한다 (`WORKLOG.md` 6.3).
- `next dev`를 실행하면 `AGENTS.md`의 Next.js 안내 블록이 다시 생성된다. 지우지 말고 그대로 둔다.
