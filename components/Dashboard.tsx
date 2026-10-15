"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

export type Vuln = {
  cve_id: string;
  vendor: string;
  product: string;
  vuln_name: string | null;
  date_added: string;
  due_date: string | null;
  short_description: string | null;
  required_action: string | null;
  ransomware: string | null;
  forensic_triage: string | null;
  notes: string | null;
  cwes: string[] | null;
  area: string;
  cve_published: string | null;
  cve_title: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_vector: string | null;
  attack_vector: string | null;
  affected: string | null;
  fixed: string | null;
  title_ko: string | null;
  summary_ko: string | null;
  scenario_ko: string | null;
  action_ko: string | null;
};

export type SyncInfo = { finished_at: string | null; catalog_version: string | null; status: string };

type Props = {
  rows: Vuln[];
  days: number;
  since: string;
  initialArea: string;
  initialCve: string | null;
  periods: number[];
  areas: { key: string; name: string }[];
  sync: SyncInfo | null;
};

const DAY = 86_400_000;
const fmt = new Intl.NumberFormat("ko-KR");

function dueInfo(due: string | null, today: number | null): { text: string; tone: string; days: number | null } {
  if (!due || today == null) return { text: "—", tone: "mut", days: null };
  const d = Math.round((Date.parse(due) - today) / DAY);
  if (d < 0) return { text: `기한 경과 ${-d}일`, tone: "bad", days: d };
  if (d === 0) return { text: "오늘 마감", tone: "bad", days: d };
  return { text: `D-${d}`, tone: d <= 3 ? "warn" : "mut", days: d };
}

const sevTone = (s: number | null) => (s == null ? "" : s >= 9 ? "bad" : s >= 7 ? "warn" : "");

export default function Dashboard({ rows, days, since, initialArea, initialCve, periods, areas, sync }: Props) {
  const router = useRouter();
  const areaName = useMemo(() => Object.fromEntries(areas.map((a) => [a.key, a.name])), [areas]);
  const [area, setArea] = useState(initialArea);
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(initialCve);
  const [today, setToday] = useState<number | null>(null);

  // 날짜 계산은 브라우저 기준(서버 렌더와 어긋나지 않도록 마운트 후 계산)
  useEffect(() => {
    const n = new Date();
    setToday(Date.UTC(n.getFullYear(), n.getMonth(), n.getDate()));
  }, []);

  const inArea = useMemo(() => rows.filter((r) => area === "all" || r.area === area), [rows, area]);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = s
      ? inArea.filter((r) =>
          [r.cve_id, r.vendor, r.product, r.vuln_name, r.title_ko].join(" ").toLowerCase().includes(s),
        )
      : inArea;
    return [...list].sort(
      (a, b) => b.date_added.localeCompare(a.date_added) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0),
    );
  }, [inArea, q]);

  const current = shown.find((r) => r.cve_id === selected) ?? shown[0] ?? null;
  const currentId = current?.cve_id ?? null;

  // 영역·선택 CVE를 주소에 반영해 링크로 공유할 수 있게 합니다.
  useEffect(() => {
    const u = new URL(window.location.href);
    u.searchParams.set("days", String(days));
    u.searchParams.set("area", area);
    if (selected && selected === currentId) u.searchParams.set("cve", selected);
    else u.searchParams.delete("cve");
    window.history.replaceState(null, "", u.toString());
  }, [area, selected, currentId, days]);

  const kpi = useMemo(() => {
    const overdue = today == null ? null : inArea.filter((r) => r.due_date && Date.parse(r.due_date) < today).length;
    return {
      total: inArea.length,
      overdue,
      network: inArea.filter((r) => r.attack_vector === "네트워크").length,
      critical: inArea.filter((r) => (r.cvss_score ?? 0) >= 9).length,
      ransomware: inArea.filter((r) => r.ransomware === "Known").length,
    };
  }, [inArea, today]);

  const urgent = useMemo(() => {
    if (today == null) return null;
    return (
      inArea
        .filter((r) => r.due_date && Date.parse(r.due_date) >= today)
        .sort((a, b) => a.due_date!.localeCompare(b.due_date!))[0] ?? null
    );
  }, [inArea, today]);

  const areaCounts = useMemo(() => {
    const m = new Map<string, number>();
    rows.forEach((r) => m.set(r.area, (m.get(r.area) ?? 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [rows]);
  const maxCount = Math.max(1, ...areaCounts.map(([, n]) => n));

  const scopeName = area === "all" ? "전체 인프라" : areaName[area];

  return (
    <main className="wrap">
      <header>
        <h1>인프라 취약점 KEV 위협 현황</h1>
        <p className="sub">
          최근 {days}일({since} 이후) CISA KEV 신규 등재 기준
          {sync?.catalog_version ? `, 카탈로그 ${sync.catalog_version}` : ""}
          {sync?.finished_at ? `, 동기화 ${new Date(sync.finished_at).toLocaleString("ko-KR")}` : ""}
        </p>
        <p className="take">
          최근 {days}일 동안 KEV에 새로 오른 {fmt.format(rows.length)}건 중 {scopeName}은(는) {fmt.format(kpi.total)}건입니다.
          {urgent && (
            <>
              {" "}가장 급한 항목은 <b>{urgent.cve_id}</b>({urgent.vendor} {urgent.product})로 조치기한이 {urgent.due_date}(
              <b className={dueInfo(urgent.due_date, today).tone}>{dueInfo(urgent.due_date, today).text}</b>)입니다.
            </>
          )}
          {kpi.overdue ? ` CISA 조치기한이 이미 지난 항목도 ${kpi.overdue}건 있습니다.` : ""}
        </p>
      </header>

      <div className="filters">
        <label>
          기간
          <select value={days} onChange={(e) => router.push(`/?days=${e.target.value}&area=${area}`)}>
            {periods.map((p) => (
              <option key={p} value={p}>
                최근 {p}일
              </option>
            ))}
          </select>
        </label>
        <label>
          영역
          <select value={area} onChange={(e) => { setArea(e.target.value); setSelected(null); }}>
            <option value="all">전체 인프라</option>
            {areas.map((a) => (
              <option key={a.key} value={a.key}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <section className="tiles" aria-label="핵심 지표">
        <Tile label="신규 등재" value={kpi.total} note={`실제 악용이 확인되어 KEV에 오른 ${scopeName} 취약점`} />
        <Tile label="조치기한 경과" value={kpi.overdue} note="CISA 조치기한이 오늘 기준으로 지난 건" tone={kpi.overdue ? "bad" : ""} />
        <Tile label="원격 공격 가능" value={kpi.network} note="공격 경로가 네트워크(AV:N)인 건" />
        <Tile label="CVSS 9.0 이상" value={kpi.critical} note="치명(Critical) 등급인 건" />
        <Tile label="랜섬웨어 악용" value={kpi.ransomware} note="CISA가 랜섬웨어 캠페인 악용을 확인한 건" tone={kpi.ransomware ? "bad" : ""} />
      </section>

      <section className="card">
        <h2>취약점 목록</h2>
        <p className="note">행을 선택하면 아래에 한국어 요약이 열립니다. 상태는 오늘 기준 CISA 조치기한까지 남은 일수입니다.</p>
        <div className="tools">
          <input type="search" placeholder="CVE, 제품, 유형 검색" aria-label="검색" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="mut small">{fmt.format(shown.length)}건</span>
        </div>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>제품</th>
                <th>유형</th>
                <th className="r">CVSS</th>
                <th>공격 경로</th>
                {area === "all" && <th>영역</th>}
                <th>KEV 등재</th>
                <th>조치기한</th>
                <th>상태</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const due = dueInfo(r.due_date, today);
                const on = current?.cve_id === r.cve_id;
                return (
                  <tr
                    key={r.cve_id}
                    className={on ? "on" : ""}
                    tabIndex={0}
                    aria-selected={on}
                    onClick={() => setSelected(r.cve_id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelected(r.cve_id);
                      }
                    }}
                  >
                    <td className="id">{r.cve_id}</td>
                    <td>{r.vendor} {r.product}</td>
                    <td>{r.title_ko ?? r.vuln_name}</td>
                    <td className={`r ${sevTone(r.cvss_score)}`}>{r.cvss_score ?? "—"}</td>
                    <td className="nw">{r.attack_vector ?? "—"}</td>
                    {area === "all" && <td className="nw">{areaName[r.area] ?? r.area}</td>}
                    <td className="nw">{r.date_added}</td>
                    <td className="nw">{r.due_date ?? "—"}</td>
                    <td className={`nw ${due.tone}`}>{due.text}</td>
                  </tr>
                );
              })}
              {!shown.length && (
                <tr>
                  <td colSpan={area === "all" ? 10 : 9} className="mut">
                    조건에 맞는 항목이 없습니다. 기간을 늘리거나 영역을 바꿔 보세요.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {current && <Detail v={current} today={today} areaName={areaName[current.area] ?? current.area} />}

      <section className="card">
        <h2>인프라 영역별 신규 등재</h2>
        <p className="note">같은 기간 KEV 신규 등재 전체 {fmt.format(rows.length)}건을 영역별로 셌습니다. 막대를 누르면 그 영역으로 바뀝니다.</p>
        <div className="bars">
          {areaCounts.map(([k, n]) => (
            <button key={k} className={`bar ${k === area ? "on" : ""}`} onClick={() => { setArea(k); setSelected(null); }}>
              <span className="t">{areaName[k] ?? k}</span>
              <span className="track">
                <span className="fill" style={{ width: `${(n / maxCount) * 100}%` }} />
                <span>{fmt.format(n)}건</span>
              </span>
            </button>
          ))}
        </div>
      </section>

      <footer>
        출처: CISA Known Exploited Vulnerabilities 카탈로그, CVE 공식 레코드(CVEProject/cvelistV5). 한국어 요약은 Claude가 원문을 바탕으로
        생성했으며, 영역 분류는 제품명 규칙에 따른 자동 분류입니다. 실제 패치 버전은 각 배포판·벤더 공지로 최종 확인하세요.
      </footer>
    </main>
  );
}

function Tile({ label, value, note, tone = "" }: { label: string; value: number | null; note: string; tone?: string }) {
  return (
    <div className="tile">
      <div className="l">{label}</div>
      <b className={tone}>{value == null ? "—" : fmt.format(value)}</b>
      <div className="n">{note}</div>
    </div>
  );
}

function Detail({ v, today, areaName }: { v: Vuln; today: number | null; areaName: string }) {
  const due = dueInfo(v.due_date, today);
  const hasKo = !!v.summary_ko;
  const links = (v.notes ?? "").match(/https?:\/\/[^\s;]+/g)?.slice(0, 4) ?? [];
  // CISA는 지원 종료 제품에 "end-of-life"나 "discontinue use" 문구를 붙입니다.
  const eol = /end[- ]of[- ](life|service|support)|\beol\b|discontinue (the )?use/i.test(
    `${v.short_description ?? ""} ${v.required_action ?? ""} ${v.notes ?? ""}`,
  );
  return (
    <article className="card detail" aria-live="polite">
      <div className="d-head">
        <div className="d-id">{v.cve_id}</div>
        <div className="d-t">{v.title_ko ?? v.vuln_name}</div>
        <div className="chips">
          <span className="chip">
            CVSS <b className={sevTone(v.cvss_score)}>{v.cvss_score ?? "정보 없음"}</b> {v.cvss_severity ?? ""}
          </span>
          <span className="chip">공격 경로 {v.attack_vector ?? "—"}</span>
          <span className="chip">랜섬웨어 악용 {v.ransomware === "Known" ? "확인됨" : "미확인"}</span>
          <span className="chip">영역 {areaName}</span>
          <span className="chip">
            상태 <b className={due.tone}>{due.text}</b>
          </span>
        </div>
      </div>
      <div className="grid">
        <section className="sec">
          <h3>무엇이 문제인가</h3>
          {hasKo ? <p>{v.summary_ko}</p> : <p className="mut">한국어 요약 대기 중입니다. 아래 원문을 참고하세요.</p>}
          <p className={hasKo ? "en" : ""}>{v.short_description}</p>
        </section>
        <section className="sec">
          <h3>공격 조건</h3>
          {v.scenario_ko ? <p>{v.scenario_ko}</p> : <p className="mut">한국어 요약 대기 중입니다.</p>}
          <dl>
            <dt>CVSS 벡터</dt>
            <dd>{v.cvss_vector ?? "—"}</dd>
            <dt>취약점 유형</dt>
            <dd>{v.cwes?.length ? v.cwes.join(", ") : "—"}</dd>
            <dt>원문 제목</dt>
            <dd>{v.cve_title ?? v.vuln_name ?? "—"}</dd>
          </dl>
        </section>
        <section className="sec">
          <h3>영향 범위</h3>
          <p>{v.affected ?? "CVE 레코드에 제품 정보가 없습니다."}</p>
          {v.fixed && <p className="en">수정 버전(이 버전 이상): {v.fixed}</p>}
        </section>
        <section className="sec">
          <h3>권장 조치</h3>
          {v.action_ko && <p>{v.action_ko}</p>}
          <p className={v.action_ko ? "en" : ""}>{v.required_action}</p>
        </section>
      </div>
      <dl className="dates">
        <dt>KEV 등재</dt>
        <dd>{v.date_added}</dd>
        <dt>CISA 조치기한</dt>
        <dd>{v.due_date ?? "—"}</dd>
        <dt>CVE 최초 공개</dt>
        <dd>{v.cve_published ?? "—"}</dd>
        <dt>침해 흔적 점검</dt>
        <dd>{v.forensic_triage === "Yes" ? "요구됨" : v.forensic_triage ?? "—"}</dd>
        <dt>지원 종료 제품 우려</dt>
        <dd className={eol ? "warn" : ""}>{eol ? "예 (교체·사용 중단 검토)" : "아니오"}</dd>
      </dl>
      {links.length > 0 && (
        <p className="en">
          참고 링크:{" "}
          {links.map((u, i) => (
            <span key={u}>
              {i > 0 && ", "}
              <a href={u} target="_blank" rel="noopener noreferrer">
                {u}
              </a>
            </span>
          ))}
        </p>
      )}
    </article>
  );
}
