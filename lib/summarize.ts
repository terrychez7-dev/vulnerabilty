// Claude API로 CVE 한국어 요약을 생성합니다. SDK 없이 Messages API를 직접 호출합니다.
// API 문서: https://docs.claude.com/en/api/messages

export type SummaryInput = {
  cve_id: string;
  vendor: string;
  product: string;
  vuln_name: string;
  short_description: string;
  required_action: string;
  due_date: string | null;
  ransomware: string;
  cwes: string[];
  notes: string;
  cve_title: string | null;
  cve_description: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  affected: string | null;
  fixed: string | null;
};

export type SummaryKo = { title_ko: string; summary_ko: string; scenario_ko: string; action_ko: string };

const SYSTEM = `당신은 금융권 인프라 보안 담당자를 돕는 취약점 분석가입니다.
CISA KEV 항목과 CVE 공식 레코드 원문을 받아, 서버·네트워크 운영자가 바로 판단할 수 있는 한국어 요약을 씁니다.

규칙:
- 원문에 없는 버전, 공격 사례, 공격 그룹, 수치를 만들어내지 마세요. 추정이 필요하면 "~일 수 있습니다"로 표현하세요.
- CVSS 벡터가 있으면 공격 경로(AV), 필요 권한(PR), 사용자 상호작용(UI), 범위(S)를 풀어서 설명하세요.
- 리눅스 등 오픈소스는 배포판마다 백포트 버전이 다르므로 배포판 보안 공지 확인을 안내하세요.
- 존댓말, 평서문으로 간결하게 씁니다.

반드시 JSON 객체 하나만 출력하세요(코드 블록, 설명 금지). 키:
- title_ko: 취약점 유형을 20자 내외로 (예: "Windows Shell 명령 주입 → 보안 기능 우회")
- summary_ko: 무엇이 문제인지 2~3문장
- scenario_ko: 공격 조건과 영향 1~2문장
- action_ko: 권장 조치 2~3문장 (패치, 임시 완화, 우선 대상 서버)`;

export async function summarizeKo(input: SummaryInput): Promise<SummaryKo & { model: string }> {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("ANTHROPIC_API_KEY 없음");
  const model = process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5";

  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-api-key": key,
    "anthropic-version": "2023-06-01",
  };
  // 워크스페이스에 속하지 않은 키는 대상 워크스페이스 ID를 함께 보내야 합니다.
  const workspaceId = process.env.ANTHROPIC_WORKSPACE_ID;
  if (workspaceId) headers["anthropic-workspace-id"] = workspaceId;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      // 짧은 요약이므로 effort를 낮춰 비용을 줄이고, 생각에 쓰는 토큰 때문에 JSON이 잘리지 않게 여유를 둡니다.
      max_tokens: 4000,
      output_config: { effort: "low" },
      system: SYSTEM,
      messages: [{ role: "user", content: JSON.stringify(input) }],
    }),
    signal: AbortSignal.timeout(90_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Claude API ${res.status}: ${body.slice(0, 200)}`);
  }
  const data = (await res.json()) as { content?: { type: string; text?: string }[]; stop_reason?: string };
  if (data.stop_reason === "max_tokens") throw new Error("요약 응답이 max_tokens에서 잘렸습니다.");
  if (data.stop_reason === "refusal") throw new Error("요약 요청이 거절되었습니다 (refusal).");
  const text = (data.content ?? []).filter((b) => b.type === "text").map((b) => b.text ?? "").join("");
  const json = text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
  const parsed = JSON.parse(json) as Partial<SummaryKo>;
  for (const k of ["title_ko", "summary_ko", "scenario_ko", "action_ko"] as const) {
    if (typeof parsed[k] !== "string" || !parsed[k]!.trim()) throw new Error(`요약 응답에 ${k}가 없습니다.`);
  }
  return { ...(parsed as SummaryKo), model };
}
