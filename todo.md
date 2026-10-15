# KEV 인프라 취약점 대시보드: Vercel 배포 할 일

- 작성일: 2026-10-16 (배포 완료 후 갱신)

## 현재 상태

| 항목 | 상태 |
|---|---|
| 운영 주소 | https://vulnerabilty-z4ua.vercel.app/ |
| GitHub | https://github.com/terrychez7-dev/vulnerabilty (`main`) |
| Supabase | 스키마 적용 완료, 백필 완료 (KEV 1,745건, CVE 보강 305건) |
| 동기화 API | 수동 실행 `ok` 확인 (`sync_runs` id 4) |
| 한국어 요약 | 0건 (`ANTHROPIC_API_KEY` 미입력) |

## 1. 프로젝트 가져오기 ✅

- [x] https://vercel.com 에 GitHub 계정(`terrychez7-dev`)으로 로그인
- [x] **Add New… → Project**
- [x] 목록에서 `vulnerabilty`를 찾아 **Import**
- [x] Framework Preset **Next.js**, Root Directory `./` 확인

## 2. 환경변수 등록 ✅

| 이름 | 값 |
|---|---|
| `SUPABASE_URL` | `.env.local` 값 그대로 |
| `SUPABASE_READ_KEY` | `.env.local` 값 그대로 |
| `SUPABASE_SECRET_KEY` | `.env.local` 값 그대로 |
| `CRON_SECRET` | `.env.local` 값 그대로 (64자 값) |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` |
| `ENRICH_DAYS` | `365` |
| `SUMMARY_DAYS` | `180` |
| `ANTHROPIC_API_KEY` | 아직 없음 (6단계에서 추가) |

- [x] 환경변수 7개 등록
- 팁: Finder에서 `.env.local` 같은 숨김 파일을 보려면 **⌘ + ⇧ + .** 를 누른다.

> `SUPABASE_SECRET_KEY`와 `CRON_SECRET`은 서버에서만 쓰인다. `NEXT_PUBLIC_` 같은 접두어를 붙이지 않는다.

## 3. Deploy ✅

- [x] 배포 완료: https://vulnerabilty-z4ua.vercel.app/
- [x] 대시보드에 데이터가 바로 표시되는 것 확인

## 4. 자동 동기화(Cron) 확인

- `vercel.json`에 따라 **매일 한국 시간 08:00**(UTC 23:00)에 `/api/sync`가 실행된다.
- [ ] 프로젝트 **Settings → Cron Jobs**에 `/api/sync`(`0 23 * * *`)가 등록돼 있는지 확인
- [ ] 2026-10-17 08:00 KST 이후 Supabase `sync_runs`에 `trigger = cron` 기록이 생기는지 확인

> Hobby(무료) 플랜은 하루 1회만 실행되고, 실행 시각이 그 시간대 안에서 조금 밀릴 수 있다. 하루 여러 번(PRD 기준 6시간 주기) 돌리려면 Pro 플랜이 필요하다.

## 5. 배포 후 확인 ✅

- [x] 화면 정상, 응답 1.3~1.7초 (첫 요청 2.85초는 콜드 스타트 포함). PRD 목표 2초 이내
- [x] 보안 헤더 적용 (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`)
- [x] 토큰 없이 / 틀린 토큰으로 `/api/sync` 호출 시 `401`
- [x] 실제 `CRON_SECRET`으로 수동 동기화 → `200`, `ok`

## 6. 나중에: 한국어 요약 켜기

- [ ] console.anthropic.com에서 API 키 발급
- [ ] 로컬 `.env.local`의 `ANTHROPIC_API_KEY`에 입력
- [ ] 로컬에서 `npm run backfill` 실행
  - 최근 180일치 약 165건의 요약을 한 번에 만든다.
  - Vercel 동기화는 실행 시간 제한 때문에 한 번에 약 40건씩만 처리한다.
- [ ] Vercel **Settings → Environment Variables**에 `ANTHROPIC_API_KEY` 추가
- [ ] **Deployments**에서 **Redeploy** (환경변수만 바꾸면 반영되지 않는다)

## 7. 1주 시범 운영 (M3)

- [ ] 매일 아침 신규 등재가 반영되는지 확인
- [ ] 영역 분류가 맞는지, 미분류 항목이 늘지 않는지 확인 (`npm run area-report`)
- [ ] PRD 미결 사항 결정: Vercel 플랜, 요약 모델과 `SUMMARY_DAYS`, 운영 도메인

## 참고

- 이 Mac의 Node는 v6이다. 로컬에서 `npm` 명령을 직접 실행하려면 Node.js 20.9 이상을 설치해야 한다.
- 폴더에 새로 생긴 `AGENTS.md`, `CLAUDE.md`는 아직 커밋하지 않았다. 필요하면 내용을 확인한 뒤 커밋한다.