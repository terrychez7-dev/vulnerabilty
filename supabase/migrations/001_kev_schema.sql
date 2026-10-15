-- CISA KEV 인프라 취약점 대시보드 스키마
-- Supabase SQL Editor에 그대로 붙여 실행하거나, supabase CLI로 마이그레이션하세요.

-- 1) KEV 원본 (카탈로그 전체 저장)
create table if not exists public.kev_vulns (
  cve_id            text primary key,
  vendor            text not null,
  product           text not null,
  vuln_name         text,
  date_added        date not null,
  due_date          date,
  short_description text,
  required_action   text,
  ransomware        text,
  forensic_triage   text,
  notes             text,
  cwes              text[] not null default '{}',
  area              text not null,               -- 인프라 영역 키 (lib/areas.ts)
  kev_hash          text not null,               -- 원본 필드 해시: 변경 감지용
  first_seen_at     timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index if not exists kev_vulns_date_added_idx on public.kev_vulns (date_added desc);
create index if not exists kev_vulns_area_date_idx  on public.kev_vulns (area, date_added desc);

-- 2) CVE 공식 레코드(cvelistV5) 보강 정보
create table if not exists public.cve_enrichment (
  cve_id        text primary key references public.kev_vulns (cve_id) on delete cascade,
  status        text not null check (status in ('ok', 'not_found', 'error')),
  published     date,
  cve_updated   timestamptz,
  title         text,
  description   text,
  cvss_score    numeric(3, 1),
  cvss_severity text,
  cvss_vector   text,
  cvss_version  text,
  attack_vector text,                             -- 네트워크 / 인접 네트워크 / 로컬 / 물리
  affected      text,
  fixed         text,
  error         text,
  fetched_at    timestamptz not null default now()
);

-- 3) Claude 한국어 요약
create table if not exists public.cve_summaries_ko (
  cve_id       text primary key references public.kev_vulns (cve_id) on delete cascade,
  title_ko     text,
  summary_ko   text,
  scenario_ko  text,
  action_ko    text,
  model        text,
  source_stamp text not null,                     -- kev_hash + cve_updated: 원문이 바뀌면 재생성
  generated_at timestamptz not null default now()
);

-- 4) 동기화 이력
create table if not exists public.sync_runs (
  id              bigint generated always as identity primary key,
  started_at      timestamptz not null default now(),
  finished_at     timestamptz,
  trigger         text,
  catalog_version text,
  kev_source      text,                           -- 실제로 받은 주소 (cisa.gov 또는 GitHub 미러)
  kev_total       int,
  kev_new         int,
  kev_changed     int,
  enriched        int,
  enrich_errors   int,
  summarized      int,
  summary_errors  int,
  pending_enrich  int,
  pending_summary int,
  status          text not null default 'running' check (status in ('running', 'ok', 'partial', 'error')),
  error           text
);
-- 이전 버전 스키마를 이미 적용한 경우를 위한 컬럼 추가
alter table public.sync_runs add column if not exists kev_source     text;
alter table public.sync_runs add column if not exists enrich_errors  int;
alter table public.sync_runs add column if not exists summary_errors int;
create index if not exists sync_runs_started_idx on public.sync_runs (started_at desc);

-- 5) 화면 조회용 뷰
create or replace view public.kev_dashboard_v
with (security_invoker = true) as
select
  v.cve_id, v.vendor, v.product, v.vuln_name, v.date_added, v.due_date,
  v.short_description, v.required_action, v.ransomware, v.forensic_triage,
  v.notes, v.cwes, v.area, v.first_seen_at,
  e.status       as enrich_status,
  e.published    as cve_published,
  e.title        as cve_title,
  e.cvss_score, e.cvss_severity, e.cvss_vector, e.attack_vector,
  e.affected, e.fixed,
  s.title_ko, s.summary_ko, s.scenario_ko, s.action_ko, s.generated_at as summary_generated_at
from public.kev_vulns v
left join public.cve_enrichment e on e.cve_id = v.cve_id
left join public.cve_summaries_ko s on s.cve_id = v.cve_id;

-- 6) RLS: 누구나 읽기만 가능, 쓰기는 secret(service_role) 키로만 (RLS 우회)
alter table public.kev_vulns        enable row level security;
alter table public.cve_enrichment   enable row level security;
alter table public.cve_summaries_ko enable row level security;
alter table public.sync_runs        enable row level security;

drop policy if exists "public read" on public.kev_vulns;
drop policy if exists "public read" on public.cve_enrichment;
drop policy if exists "public read" on public.cve_summaries_ko;
drop policy if exists "public read" on public.sync_runs;

create policy "public read" on public.kev_vulns        for select to anon, authenticated using (true);
create policy "public read" on public.cve_enrichment   for select to anon, authenticated using (true);
create policy "public read" on public.cve_summaries_ko for select to anon, authenticated using (true);
create policy "public read" on public.sync_runs        for select to anon, authenticated using (true);

grant select on public.kev_dashboard_v to anon, authenticated;
