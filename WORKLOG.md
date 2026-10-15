# 작업 기록: KEV 인프라 취약점 대시보드

- 작성일: 2026-10-15 (최종 수정 2026-10-16, 6장 추가)
- 기준 문서: `PRD.md` (v1.1)
- 프로젝트 경로: `/Users/teslla/Desktop/CLAUDE/a/kev-dashboard-vercel`
- 원격 저장소: https://github.com/terrychez7-dev/vulnerabilty (push 완료)

## 1. 요약

PRD와 같은 폴더에 있던 `kev-dashboard-vercel.zip`에 PRD 기반 구현이 이미 대부분 들어 있었다. 그래서 처음부터 새로 만들지 않고, 압축을 풀어 PRD 요구사항과 하나씩 대조한 뒤 빠진 기능과 버그를 보완했다.

| 구분 | 결과 |
|---|---|
| 타입 검사 (`npm run typecheck`) | 통과 |
| 프로덕션 빌드 (`npm run build`) | 통과 |
| 보안 점검 (`npm audit`) | 취약점 0건 |
| KEV 실데이터 수집 | 성공 (카탈로그 2026.10.14, 1,745건) |
| CVE 보강 실데이터 | 성공 (CVE-2024-3400 → CVSS 10, 네트워크 / 없는 CVE → `not_found`) |
| Supabase 연동 | 2026-10-16 검증 완료 (6장) |
| Vercel 배포, 동기화 API | 2026-10-16 검증 완료 (6.6) |
| Claude 요약, Vercel Cron 자동 실행 | **미검증** (Claude 키 미입력, 첫 Cron 실행 전) |

## 2. PRD 대비 보완 내용

### 2.1 요약 재생성 버그 수정 (F-SUM-03, N-07)

- **문제**: KEV 변경 감지 해시(`kev_hash`)에 영역 분류 결과가 포함되어 있었다. 분류 규칙만 바꿔도 모든 항목이 "변경"으로 처리되어, 최근 365일치 CVE 보강과 180일치 Claude 요약이 전부 다시 실행됐다. Claude API 비용이 크게 늘어나는 부분이다.
- **수정**: 해시는 KEV 원본 필드로만 만든다. 동기화 때 영역은 따로 비교해서, 분류만 바뀐 항목은 `area`만 다시 저장하고 `updated_at`은 그대로 둔다.
- **파일**: `lib/kev.ts`, `lib/sync.ts`

### 2.2 동기화 이력 보강 (F-SYNC-08, F-SUM-05)

- `sync_runs`에 컬럼 3개를 추가했다.
  - `kev_source`: 실제로 받은 주소 (cisa.gov 또는 GitHub 미러)
  - `enrich_errors`: CVE 보강 오류 건수
  - `summary_errors`: 요약 실패 건수
- 요약이나 보강이 실패한 실행은 상태를 `partial`로 남긴다.
- `error` 칸에 실패 건수와 `ANTHROPIC_API_KEY` 누락 여부를 기록한다.
- 이미 스키마를 적용한 DB에서도 실행되도록 `alter table ... add column if not exists` 구문을 넣었다.
- **파일**: `lib/sync.ts`, `supabase/migrations/001_kev_schema.sql`

### 2.3 동기화 API 인증 강화 (F-SYNC-04)

- `Authorization: Bearer <CRON_SECRET>` 비교를 `timingSafeEqual`로 바꿨다. 타이밍 공격을 막기 위한 것이다.
- **파일**: `app/api/sync/route.ts`

### 2.4 영역 분류 점검 도구와 규칙 보완 (F-AREA-03)

- `npm run area-report`를 새로 만들었다. DB 없이 KEV 피드를 직접 받아 아래 내용을 출력한다.
  - 영역별 건수 (전체 기간 / 최근 N일)
  - 미분류 비율과 목표(15% 이하) 충족 여부
  - 미분류 상위 벤더·제품 25개
- 규칙은 인프라 성격이 분명한 제품만 추가했다.

| 영역 | 추가한 제품 |
|---|---|
| 네트워크 | LoadMaster, DD-WRT, Fortinet Multiple Products |
| 운영·원격관리 | PaperCut |
| 미들웨어·서버 SW | Roundcube, Gitea, Starlette, Kestra, ownCloud, Nextcloud, MLflow, Ray, LiteLLM, Langflow |

- Fortinet은 "Multiple Products"로 한정했다. 벤더명 전체를 잡으면 FortiMail 같은 보안 제품까지 네트워크 영역으로 넘어가기 때문이다. 수정 후에도 보안 영역 건수(60건)는 그대로였다.
- 결과:

| 범위 | 수정 전 | 수정 후 |
|---|---|---|
| 전체 기간 미분류 | 394 / 1,745 (22.6%) | 353 / 1,745 (20.2%) |
| 최근 90일 미분류 | 26 / 98 (26.5%) | 12 / 98 (12.2%) — 목표 충족 |

- **파일**: `scripts/area-report.ts`, `lib/areas.ts`, `package.json`

### 2.5 상세 화면 보완 (F-UI-07, F-UI-09, F-SUM-06)

- 한국어 요약이 없으면 "한국어 요약 대기 중입니다. 아래 원문을 참고하세요."를 표시한다.
- 지원 종료 제품 판단: 기존에는 설명문의 "end-of-life"만 봤다. 이제 조치 문구와 notes까지 보고, "end of service/support", "EoL", "discontinue use" 같은 표현도 잡는다. 해당하면 주의 색으로 "예 (교체·사용 중단 검토)"를 표시한다.
- 영역을 바꿔 선택한 CVE가 목록에서 빠지면, 주소의 `?cve=` 값도 함께 지운다.
- 영역이 '전체 인프라'일 때 표가 10열이 되므로, 결과 없음 안내 행도 10칸을 차지하도록 고쳤다 (2026-10-15 재점검).
- **파일**: `components/Dashboard.tsx`

### 2.6 의존성 보안 (N-04)

- `next` 16.3.7에 high 등급 보안 권고가 있었다 (캐시 포이즈닝, SSRF 등).
- 공개 후 2주가 지난 패치 버전 16.3.8(2026-09-30 공개)로 올렸다. 이후 `npm audit` 결과는 0건이다.

### 2.7 문서

- README에 Node.js 20.9 이상 요구, `area-report` 사용법, `sync_runs` 추가 컬럼 설명을 반영했다.

## 3. PRD 요구사항 대응 현황

| 영역 | 요구사항 | 상태 |
|---|---|---|
| 수집·동기화 | F-SYNC-01 ~ 10 | 구현 (01~04, 07, 08 보완) |
| 영역 분류 | F-AREA-01 ~ 03 | 구현 (03 점검 도구 추가) |
| 한국어 요약 | F-SUM-01 ~ 06 | 구현 (03, 05, 06 보완) |
| 대시보드 | F-UI-01 ~ 12 | 구현 (07, 09 보완) |
| 비기능 | N-01 ~ 09 | 구현 (04 패치 반영). N-05 성능은 실데이터 연결 후 확인 필요 |
| v2 후보 | 자산 대조, 알림 등 | 범위 밖 (PRD 2.2, 10장) |

## 4. 저장소 작업

| 단계 | 내용 |
|---|---|
| `git init` | `kev-dashboard-vercel/`에 저장소 생성, 브랜치 `main` |
| `.gitignore` | `.DS_Store` 추가 (macOS 자동 생성 파일 제외) |
| 커밋 `63cfbba` | KEV 인프라 취약점 대시보드 v1 구현 (23개 파일) |
| 원격 연결 | `origin` = https://github.com/terrychez7-dev/vulnerabilty.git |
| 커밋 `69cc0c6` | 원격의 자동 생성 README 커밋(`fa325f3`)을 이력 보존하며 병합, 프로젝트 README 유지 |
| push (2026-10-15) | **실패**: 이 Mac에 GitHub 인증 정보가 없음 → 2026-10-16 해결 (6.1) |

## 5. 남은 일 (2026-10-16 기준)

1. ~~Node.js 설치~~: 완료 (6.7)
2. ~~GitHub push~~: 완료 (6.1)
3. ~~Supabase 구성 (M1)~~: 완료 (6.2)
4. **최초 백필과 검증 (M2)**: KEV 저장과 CVE 보강은 완료했다 (6.3). 남은 일은 `ANTHROPIC_API_KEY`를 넣고 `npm run backfill`로 한국어 요약을 만든 뒤 품질을 샘플링하는 것이다.
5. **Vercel 배포 (M3)**: 배포와 동기화 API 확인은 완료했다 (6.6). 남은 일은 다음과 같다.
   - Settings → Cron Jobs에서 `/api/sync` 등록 여부를 확인한다.
   - 다음 날 08:00 KST 이후 `sync_runs`에 `trigger = cron` 기록이 생기는지 확인한다.
   - 1주 시범 운영을 한다.
6. **PRD 미결 사항 (12장)**: Vercel 플랜, 요약 모델과 `SUMMARY_DAYS`, 운영 도메인을 결정한다.

## 6. 2026-10-16 작업

### 6.1 Git 설정과 GitHub push

- 전역 git 설정을 `user.name = terrychez7-dev`로 바꿨다. 이메일과 기본 브랜치(`main`)는 그대로다.
- 사용자가 터미널에서 토큰으로 push했지만 `rejected (fetch first)`로 거부됐다.
  - 원인: GitHub 저장소가 2026-10-15 23:48 KST에 다시 만들어져 있었다. 원격에는 부모가 없는 새 초기 커밋 `38b7ab7`(README 2줄) 하나만 있었다.
  - 이 README 내용은 기존 `fa325f3`과 같아서, 덮어써도 잃는 내용이 없었다.
- 사용자 결정에 따라 `--force-with-lease=main:38b7ab7`로 강제 push했다. 그 사이 원격이 바뀌었다면 거부되도록 한 것이다.
- 이후 push는 Keychain에 저장된 토큰으로 바로 된다.

| 커밋 | 내용 |
|---|---|
| `ef7596b` | 목록 '결과 없음' 행이 전체 영역 보기(10열)에서 모든 열을 차지하도록 수정 |
| `50320a0` | `WORKLOG.md` 추가 |
| `ec2ab22` | CVE 보강 저장이 WAF에 막혀도 동기화가 멈추지 않도록 수정 (6.3) |

### 6.2 Supabase 연결 확인 (M1)

- 처음에는 `.env.local`의 `SUPABASE_URL`이 예시값(`xxxxxxxx`) 그대로였다. 사용자가 프로젝트 URL로 고쳤다.
  - 처음 받은 주소는 조직(Organization) 페이지 주소라서 쓸 수 없었다.
- 확인 결과:

| 항목 | 결과 |
|---|---|
| 테이블 4개, 뷰 `kev_dashboard_v` | 읽기 키와 secret 키 모두 조회 성공 |
| `sync_runs` 추가 컬럼 3개 | 있음 |
| RLS: 읽기 키로 `sync_runs` insert 시도 | 차단 (`42501`) |

- `CRON_SECRET`은 `openssl rand -hex 32`로 만들어 `.env.local`에 넣었다. Vercel에도 같은 값을 등록한다.

### 6.3 최초 백필 (M2)과 WAF 차단 수정

- 첫 실행은 `cve_enrichment 저장 실패`로 중단됐다 (`sync_runs` id 2, `error`).
  - 응답이 Cloudflare 차단 페이지였다. Supabase 앞단 WAF가 요청 본문을 공격으로 판단한 것이다.
  - 한 건씩 저장해 보니 CVE-2025-24893(XWiki) 하나만 막혔다. CVE 원문 설명 끝에 공격 재현 코드가 들어 있었다.
- 수정 (`lib/sync.ts`):
  - 200건 묶음 저장이 실패하면 한 건씩 저장한다.
  - 그래도 막히는 항목은 `description`만 비우고, `error`에 "원문 설명 저장 차단(WAF)"을 남긴다.
  - KEV 원문과 CVSS 정보는 정상으로 저장된다.
- 진단용 임시 스크립트는 지웠다. 진단 중 정상 저장된 104건은 유지했고, XWiki 항목은 지운 뒤 새 코드로 다시 저장했다.
- 재실행 결과 (`sync_runs` id 3, `ok`):

| 항목 | 결과 |
|---|---|
| KEV 저장 | 1,745건 (카탈로그 2026.10.14) |
| CVE 보강 (최근 365일) | 305건 모두 `ok`, CVSS 점수 305건 모두 있음 |
| 한국어 요약 | 0건 (`ANTHROPIC_API_KEY` 없음: 요약 생략) |

### 6.4 로컬 화면 확인

`next dev`로 띄워 서버 렌더 결과를 확인했다.

| 화면 | 결과 |
|---|---|
| 기본 (30일, 서버 OS·가상화) | 전체 신규 35건 중 4건, 원격 공격 가능 2건, CVSS 9.0 이상 1건 |
| 365일, 전체 | 305건, 원격 공격 가능 255건, CVSS 9.0 이상 137건, 랜섬웨어 악용 30건 |
| 90일, 네트워크 | 29건, 목록 29행 |

- 응답 시간: 첫 요청 2.5초(개발 서버 첫 컴파일 포함), 이후 0.3~0.8초. 운영 환경 기준 N-05(2초 이내)는 배포 후 다시 확인한다.
- '조치기한 경과'는 서버 HTML에서 '—'로 나온다. 오늘 날짜를 브라우저에서 계산하도록 만든 의도된 동작이다.

### 6.5 문서

- `todo.md`: Vercel 배포 절차를 할 일 목록으로 정리했다. 임시 사본이던 `todo.txt`는 지웠다.
- `PRD.md` v1.1: 미분류 비율 현행화(F-AREA-03), 일정 진행 상태(9장), WAF 차단 리스크(11장), 수정 이력을 반영했다.

### 6.6 Vercel 배포 확인 (M3)

- 운영 주소: https://vulnerabilty-z4ua.vercel.app/
- 사용자가 GitHub 저장소를 Import하고 환경변수 7개를 등록해 배포했다. `ANTHROPIC_API_KEY`는 아직 넣지 않았다.

| 확인 항목 | 결과 |
|---|---|
| 기본 화면 (30일, 서버 OS·가상화) | 정상. 신규 35건 중 4건, 목록 4행 |
| 365일, 전체 | 정상. 305건, 목록 305행 |
| 응답 시간 (N-05) | 첫 요청 2.85초(콜드 스타트 포함), 이후 1.3초, 365일 전체 1.7초 |
| 보안 헤더 (N-03) | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` 적용 |
| `/api/sync` 토큰 없음 / 틀린 토큰 (F-SYNC-04) | 둘 다 `401` |
| `/api/sync` 실제 토큰으로 수동 실행 (F-SYNC-10) | `200`, `ok`, 5.2초 (`sync_runs` id 4). 신규·변경 0건, 보강 대기 0건 |

- 수동 실행이 통과했으므로 Vercel의 `CRON_SECRET`이 로컬 값과 같다는 것도 확인됐다.
- Cron 등록 화면은 로그인이 필요해 확인하지 못했다. 첫 자동 실행은 2026-10-17 08:00 KST 예정이다.

### 6.7 Node.js 22 설치

- `brew install node`는 실패했다. 이 Mac은 macOS 12.7.6(Intel)인데, Homebrew가 이 버전용 미리 빌드된 패키지를 더 이상 제공하지 않는다(Tier 3). 그래서 의존 라이브러리 `simdutf`를 소스에서 빌드하다가 실패했다.
- 대신 nodejs.org 공식 설치 파일 `node-v22.20.0.pkg`로 설치했다. 기존 v6.10.3도 같은 공식 설치 파일(`org.nodejs.node.pkg`)로 깔려 있었기 때문에 `/usr/local/bin/node`가 그대로 교체됐다.
- 확인: `node -v` v22.20.0, `npm -v` 10.9.3, 프로젝트 폴더에서 `npm run typecheck` 통과.
- 처음 `npm run typecheck`가 `ENOENT package.json`으로 실패한 것은 홈 폴더에서 실행했기 때문이다. 프로젝트 폴더에서 실행하면 된다.
- Node 24 이상은 macOS 13.5 이상이 필요하므로 이 Mac에서는 22.x LTS를 유지한다.
