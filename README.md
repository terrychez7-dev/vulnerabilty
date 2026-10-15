# 인프라 취약점 KEV 위협 현황 (Vercel + Supabase)

CISA KEV(실제 악용이 확인된 취약점) 카탈로그 전체를 Supabase에 저장하고, 화면에서 인프라 영역·기간별로 보여주는 대시보드입니다.

## 동작 방식

매일 1회 Vercel Cron이 `/api/sync`를 호출하고, 아래 순서로 처리합니다.

1. KEV 전체를 수집해 신규·변경분만 저장합니다. cisa.gov에서 받지 못하면 GitHub 공식 미러를 씁니다.
2. 제품명 규칙으로 인프라 영역을 분류합니다. 규칙은 `lib/areas.ts`에 있습니다.
3. 최근 `ENRICH_DAYS`일 항목은 CVE 공식 레코드(cvelistV5)로 CVSS, 공격 경로, 영향 제품, 수정 버전을 보강합니다.
4. 최근 `SUMMARY_DAYS`일 항목은 Claude API로 한국어 요약을 만듭니다. 원문이 바뀌면 요약도 다시 만듭니다.
5. 한 번에 다 처리하지 못한 건은 다음 실행으로 넘어갑니다.

화면 구성은 지표 5종, 검색 가능한 목록, 행을 선택하면 열리는 한국어 상세 요약, 영역별 건수 비교입니다. 기간은 30·90·180·365일, 영역은 8개 또는 전체 중에서 고를 수 있습니다. 주소에 `?days=30&area=server_os&cve=CVE-...`가 붙으므로 특정 CVE 화면을 링크로 공유할 수 있습니다.

## 구성 파일

| 경로 | 역할 |
|---|---|
| `supabase/migrations/001_kev_schema.sql` | 테이블 4개, 조회 뷰, RLS(누구나 읽기 전용) |
| `lib/kev.ts` | KEV 수집, 행 변환, 변경 감지용 해시 |
| `lib/areas.ts` | 인프라 영역 분류 규칙 |
| `lib/cve.ts` | CVE 레코드 보강(CVSS, 영향, 수정 버전) |
| `lib/summarize.ts` | Claude 한국어 요약 (프롬프트 수정은 여기서) |
| `lib/sync.ts` | 동기화 전체 흐름, 시간 예산 관리 |
| `app/api/sync/route.ts` | Cron 엔드포인트 (CRON_SECRET 인증) |
| `app/page.tsx`, `components/Dashboard.tsx` | 대시보드 화면 |
| `scripts/backfill.ts` | 최초 구축용 로컬 일괄 처리 |
| `scripts/area-report.ts` | 영역 분류 점검 (미분류 비율, 미분류 상위 제품) |

## 설치 순서

### 1. Supabase

1. 프로젝트를 만듭니다. 리전은 Northeast Asia (Seoul)을 권장합니다.
2. SQL Editor에서 `supabase/migrations/001_kev_schema.sql`을 그대로 실행합니다.
3. Project Settings > API Keys에서 아래 세 값을 복사해 둡니다.
   - URL
   - 읽기용 키: anon 또는 publishable
   - 쓰기용 키: service_role 또는 secret

### 2. 로컬에서 최초 데이터 채우기

Node.js 20.9 이상이 필요합니다.

```bash
cp .env.example .env.local   # 값 채우기
npm install
npm run backfill             # KEV 전체 저장 + 최근 1년 보강 + 최근 180일 요약
npm run dev                  # http://localhost:3000
```

Vercel 함수는 실행 시간 제한이 있어 처음 수백 건을 한 번에 처리하기 어렵습니다. 그래서 최초 1회는 로컬에서 채우는 것을 권장합니다.

### 3. Vercel 배포

1. GitHub 저장소에 올린 뒤 Vercel에서 Import합니다. Next.js는 자동 인식됩니다.
2. Settings > Environment Variables에 `.env.example`의 항목을 모두 등록합니다. `CRON_SECRET`은 `openssl rand -hex 32` 등으로 만든 긴 문자열을 넣습니다.
3. 배포하면 `vercel.json`의 Cron이 등록됩니다. 매일 UTC 23:00, 즉 한국 시간 오전 8시에 실행됩니다.
4. 수동 실행이 필요하면 아래처럼 호출합니다.

```bash
curl -H "Authorization: Bearer $CRON_SECRET" https://<도메인>/api/sync
```

## 운영 참고

- **Cron 주기**: Vercel Hobby 플랜은 하루 1회만 가능합니다. 더 자주 돌리려면 Pro 플랜에서 `vercel.json`의 schedule을 바꾸세요(예: `0 */6 * * *`).
- **실행 시간**: `maxDuration`은 300초로 설정돼 있습니다. 플랜 한도가 더 낮으면 `app/api/sync/route.ts`에서 줄이세요. 남은 작업은 자동으로 다음 실행에 처리됩니다.
- **요약 비용**: 신규 KEV는 보통 하루 0~10건이라 일상 운영 비용은 작습니다. 비용이 큰 시점은 최초 백필로, `SUMMARY_DAYS` 범위만큼 생성됩니다. 모델은 `ANTHROPIC_MODEL`로 바꿀 수 있습니다.
- **분류 수정**: `npm run area-report`로 미분류 비율과 상위 미분류 제품을 확인한 뒤 `lib/areas.ts`를 고쳐 배포하면, 다음 동기화 때 영역만 다시 저장됩니다. 분류가 바뀌어도 CVE 보강·한국어 요약은 다시 만들지 않습니다(목표: 최근 90일 미분류 15% 이하).
- **상태 확인**: Supabase의 `sync_runs` 테이블에서 실행 결과, 수집 출처(cisa.gov/미러), 보강·요약 실패 건수, 대기 건수, 오류를 볼 수 있습니다. 대기나 실패가 있으면 상태는 `partial`입니다.
- **보안**: 화면은 읽기 키로 조회하고, RLS로 쓰기를 막습니다. 쓰기 키는 서버(동기화)에서만 쓰며 브라우저로 전달되지 않습니다.
- **패키지 버전**: 배포 전 `npm outdated`와 `npm audit`으로 최신 보안 패치를 확인하세요.
