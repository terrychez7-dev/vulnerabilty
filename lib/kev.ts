import { createHash } from "node:crypto";
import { classify } from "./areas";

export const KEV_URLS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  // CISA 공식 GitHub 미러 (원본 실패 시)
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
];

export type KevCatalog = {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
};

export type KevEntry = {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
  cwes?: string[];
  forensicTriage?: string;
};

export type KevRow = {
  cve_id: string;
  vendor: string;
  product: string;
  vuln_name: string;
  date_added: string;
  due_date: string | null;
  short_description: string;
  required_action: string;
  ransomware: string;
  forensic_triage: string | null;
  notes: string;
  cwes: string[];
  area: string;
  kev_hash: string;
};

export async function fetchJson<T>(url: string, timeoutMs = 30_000): Promise<T> {
  const res = await fetch(url, {
    headers: { "user-agent": "kev-infra-dashboard/1.0", accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs),
    cache: "no-store",
  });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} ${url}`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

export async function fetchKev(): Promise<{ catalog: KevCatalog; source: string }> {
  const errors: string[] = [];
  for (const url of KEV_URLS) {
    try {
      const catalog = await fetchJson<KevCatalog>(url);
      if (!Array.isArray(catalog.vulnerabilities)) throw new Error("vulnerabilities 필드 없음");
      return { catalog, source: url };
    } catch (e) {
      errors.push(`${url}: ${(e as Error).message}`);
    }
  }
  throw new Error(`KEV 수집 실패 (${errors.join(" | ")})`);
}

export function toRow(v: KevEntry): KevRow {
  const base = {
    cve_id: v.cveID.trim(),
    vendor: (v.vendorProject || "").trim(),
    product: (v.product || "").trim(),
    vuln_name: (v.vulnerabilityName || "").trim(),
    date_added: v.dateAdded,
    due_date: v.dueDate || null,
    short_description: v.shortDescription || "",
    required_action: v.requiredAction || "",
    ransomware: v.knownRansomwareCampaignUse || "Unknown",
    forensic_triage: v.forensicTriage ?? null,
    notes: v.notes || "",
    cwes: v.cwes ?? [],
  };
  const area = classify(base.vendor, base.product, base.vuln_name);
  // 해시는 KEV 원본 필드만으로 만듭니다. 분류(area)는 동기화 때 별도로 비교해, 규칙이 바뀌면
  // 영역만 다시 저장하고 CVE 보강·한국어 요약은 다시 만들지 않습니다.
  const kev_hash = createHash("sha256").update(JSON.stringify(base)).digest("hex").slice(0, 32);
  return { ...base, area, kev_hash };
}
