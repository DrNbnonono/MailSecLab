"use client";
import { useDeferredValue, useState } from "react";
import type { MailReport } from "@/lib/report";
import { Icon } from "./icons";

export function ReportSections({
  report,
  onSelect,
}: {
  report: MailReport;
  onSelect: (id: string) => void;
}) {
  const [tab, setTab] = useState<"auth" | "warnings" | "headers">("auth");
  const [search, setSearch] = useState("");
  const query = useDeferredValue(search.toLowerCase());
  const [page, setPage] = useState(0);
  const fields = report.headers.filter((field) =>
    `${field.name || ""} ${field.raw}`.toLowerCase().includes(query),
  );
  return (
    <section className="panel detail-panel">
      <div className="detail-tabs" role="tablist" aria-label="报告详情">
        <button
          role="tab"
          aria-selected={tab === "auth"}
          onClick={() => setTab("auth")}
        >
          认证声明 <span>3</span>
        </button>
        <button
          role="tab"
          aria-selected={tab === "warnings"}
          onClick={() => setTab("warnings")}
        >
          异常与缺陷{" "}
          <span>{report.warnings.length + report.defects.length}</span>
        </button>
        <button
          role="tab"
          aria-selected={tab === "headers"}
          onClick={() => setTab("headers")}
        >
          邮件头 <span>{report.headers.length}</span>
        </button>
      </div>
      {tab === "auth" && (
        <div className="auth-section" role="tabpanel">
          <p className="section-note">
            下列结果由邮件头声明，MailTrace 未主动验证其真实性。
          </p>
          <div className="auth-cards">
            {(["spf", "dkim", "dmarc"] as const).map((method) => {
              const summary = report.authentication.summary[method];
              const assertions = report.authentication.assertions.filter(
                (item) => item.method === method,
              );
              return (
                <article key={method} className="auth-card">
                  <div className="auth-card-top">
                    <h3>{method.toUpperCase()}</h3>
                    <span className="pill subtle">头部声明</span>
                  </div>
                  <strong
                    className={`auth-result ${summary.reported_results.includes("fail") ? "negative" : ""}`}
                  >
                    {summary.status === "mixed"
                      ? "MIXED"
                      : summary.reported_results.join(" / ").toUpperCase() ||
                        "UNKNOWN"}
                  </strong>
                  <p>
                    {assertions.length
                      ? `${assertions.length} 条声明 · 未主动验证`
                      : "邮件头未提供结果"}
                  </p>
                  {assertions.map((assertion) => (
                    <button
                      key={assertion.id}
                      className="assertion-link"
                      onClick={() => onSelect(assertion.header_id)}
                    >
                      <span title={assertion.authserv_id || "未知来源"}>
                        {assertion.authserv_id || "未知来源"}
                      </span>
                      <span>{assertion.result} ↗</span>
                    </button>
                  ))}
                </article>
              );
            })}
          </div>
          {!!report.authentication.received_spf.length && (
            <div className="aux-auth">
              <strong>Received-SPF</strong>
              {report.authentication.received_spf.map((item) => (
                <button
                  key={item.header_id}
                  className="text-button"
                  onClick={() => onSelect(item.header_id)}
                >
                  {item.result || "unknown"} · {item.header_id} ↗
                </button>
              ))}
            </div>
          )}
          {(!!report.authentication.dkim_signatures.length ||
            !!report.authentication.arc_headers.length) && (
            <div className="aux-auth">
              <strong>签名与 ARC 证据</strong>
              {report.authentication.dkim_signatures.map((item) => (
                <button
                  className="text-button"
                  key={item.header_id}
                  onClick={() => onSelect(item.header_id)}
                >
                  DKIM · {item.domain || "未知域"} ↗
                </button>
              ))}
              {report.authentication.arc_headers.map((item) => (
                <button
                  className="text-button"
                  key={item.header_id}
                  onClick={() => onSelect(item.header_id)}
                >
                  {item.name} ↗
                </button>
              ))}
              <span>仅展示存在与原文，未验证签名或 ARC 链。</span>
            </div>
          )}
        </div>
      )}
      {tab === "warnings" && (
        <div className="findings-section" role="tabpanel">
          <p className="section-note">
            启发式提示是调查线索，不代表已确认伪造或恶意邮件。
          </p>
          {!report.warnings.length && !report.defects.length && (
            <p className="empty-note">未触发已配置规则。邮件来源仍未验证。</p>
          )}
          {report.warnings.map((finding, index) => (
            <article
              className={`finding ${finding.severity}`}
              key={`${finding.code}-${index}`}
            >
              <Icon name="alert" />
              <div>
                <strong>{finding.message}</strong>
                <code>{finding.code}</code>
                <div className="evidence-links">
                  {finding.header_ids.map((id) => (
                    <button key={id} onClick={() => onSelect(id)}>
                      {id} ↗
                    </button>
                  ))}
                </div>
              </div>
              <span
                className={`pill ${finding.severity === "warning" ? "amber" : "subtle"}`}
              >
                {finding.severity === "warning" ? "需核查" : "信息"}
              </span>
            </article>
          ))}
          {report.defects.map((defect, index) => (
            <article className="finding parser" key={`defect-${index}`}>
              <Icon name="file" />
              <div>
                <strong>{defect.message}</strong>
                <code>{defect.code}</code>
                {defect.header_id && (
                  <div className="evidence-links">
                    <button onClick={() => onSelect(defect.header_id!)}>
                      {defect.header_id} ↗
                    </button>
                  </div>
                )}
              </div>
              <span className="pill subtle">解析缺陷</span>
            </article>
          ))}
        </div>
      )}
      {tab === "headers" && (
        <div className="headers-section" role="tabpanel">
          <div className="header-search">
            <Icon name="search" />
            <input
              aria-label="搜索邮件头"
              placeholder="搜索字段名或原文…"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(0);
              }}
            />
            <span>{fields.length} 个字段</span>
          </div>
          {!fields.length && (
            <p className="empty-note">没有匹配的邮件头字段。</p>
          )}
          {fields.slice(page * 50, page * 50 + 50).map((field) => (
            <details className="header-row" key={field.id}>
              <summary>
                <strong>{field.name || "畸形字段"}</strong>
                <span className="mono">{field.id}</span>
                {!field.recognized && (
                  <span className="pill amber">未识别</span>
                )}
                <span className="header-preview">
                  {field.value?.slice(0, 100) || "原始证据"}
                </span>
              </summary>
              <pre>{field.raw.slice(0, 65_536)}</pre>
              {field.raw.length > 65_536 && (
                <p className="limit-note">
                  原文较长，完整内容可下载 JSON 查看。
                </p>
              )}
              <button
                className="text-button"
                onClick={() => onSelect(field.id)}
              >
                查看证据位置 ↗
              </button>
            </details>
          ))}
          {fields.length > 50 && (
            <div className="pagination">
              <button disabled={page === 0} onClick={() => setPage(page - 1)}>
                上一页
              </button>
              <span>
                {page + 1} / {Math.ceil(fields.length / 50)}
              </span>
              <button
                disabled={(page + 1) * 50 >= fields.length}
                onClick={() => setPage(page + 1)}
              >
                下一页
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
