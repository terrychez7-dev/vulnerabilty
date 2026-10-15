import { createClient, type SupabaseClient } from "@supabase/supabase-js";

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`환경변수 ${name}가 설정되지 않았습니다.`);
  return v;
}

/** 화면 조회용: anon/publishable 키, RLS 읽기 전용 */
export function readClient(): SupabaseClient {
  return createClient(env("SUPABASE_URL"), env("SUPABASE_READ_KEY"), {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

/** 동기화 전용: secret/service_role 키. 서버 코드(API 라우트, 스크립트)에서만 사용하세요. */
export function adminClient(): SupabaseClient {
  if (typeof window !== "undefined") throw new Error("adminClient는 서버에서만 사용할 수 있습니다.");
  return createClient(env("SUPABASE_URL"), env("SUPABASE_SECRET_KEY"), {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

/** PostgREST 기본 1,000행 제한을 넘는 테이블을 페이지 단위로 모두 읽습니다. */
export async function selectAll<T>(db: SupabaseClient, table: string, columns: string, pageSize = 1000): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await db.from(table).select(columns).order("cve_id").range(from, from + pageSize - 1);
    if (error) throw new Error(`${table} 조회 실패: ${error.message}`);
    out.push(...((data ?? []) as T[]));
    if (!data || data.length < pageSize) return out;
  }
}
