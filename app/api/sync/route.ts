import { timingSafeEqual } from "node:crypto";
import { revalidatePath } from "next/cache";
import { runSync } from "@/lib/sync";

export const dynamic = "force-dynamic";
export const maxDuration = 300; // Vercel Fluid Compute 기준. 플랜 한도에 맞게 조정하세요.

function authorized(header: string | null, secret: string | undefined): boolean {
  if (!secret || !header) return false;
  const a = Buffer.from(header);
  const b = Buffer.from(`Bearer ${secret}`);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Vercel Cron은 CRON_SECRET이 설정돼 있으면 Authorization: Bearer <CRON_SECRET> 헤더를 붙여 호출합니다.
export async function GET(req: Request) {
  if (!authorized(req.headers.get("authorization"), process.env.CRON_SECRET)) {
    return new Response("Unauthorized", { status: 401 });
  }
  try {
    const result = await runSync({
      trigger: req.headers.get("user-agent")?.includes("vercel-cron") ? "cron" : "manual",
      budgetMs: (maxDuration - 30) * 1000,
      log: (m) => console.log(`[sync] ${m}`),
    });
    revalidatePath("/");
    return Response.json(result);
  } catch (e) {
    console.error("[sync] failed", e);
    return Response.json({ error: (e as Error).message }, { status: 500 });
  }
}
