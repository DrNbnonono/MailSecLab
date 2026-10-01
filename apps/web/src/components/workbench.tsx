"use client";
import { useEffect, useRef, useState } from "react";
import type { MailReport } from "@/lib/report";
import { Icon } from "./icons";
import { InputPanel } from "./input-panel";
import { TraceRoute } from "./trace-route";
import { EvidencePanel } from "./evidence-panel";
import { ReportSections } from "./report-sections";

export function Workbench() {
  const [raw, setRaw] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [limit, setLimit] = useState(50);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<MailReport | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [revision, setRevision] = useState(0);
  const requestId = useRef(0);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);

  function invalidate() {
    requestId.current += 1;
    controller.current?.abort();
    setBusy(false);
    setError(null);
    if (report) setDirty(true);
  }
  function chooseText(value: string) {
    invalidate();
    setRaw(value);
    setFile(null);
  }
  function chooseFile(value: File | null) {
    invalidate();
    setFile(value);
    if (value) setRaw("");
  }
  function clear() {
    invalidate();
    setRaw("");
    setFile(null);
    setReport(null);
    setSelected(null);
    setDirty(false);
  }
  function select(id: string) {
    setSelected(id);
    if (window.innerWidth < 1100)
      document
        .getElementById("evidence-panel")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  async function submit() {
    if (!Number.isInteger(limit) || limit < 1) {
      setError("链长阈值必须是正整数。");
      return;
    }
    if (!file && new TextEncoder().encode(raw).length > 10 * 1024 * 1024) {
      setError("邮件内容超过 10 MiB 上限。");
      return;
    }
    controller.current?.abort();
    const pending = new AbortController();
    controller.current = pending;
    const id = ++requestId.current;
    setBusy(true);
    setError(null);
    if (report) setDirty(true);
    try {
      let body: BodyInit;
      let headers: HeadersInit | undefined;
      if (file) {
        const form = new FormData();
        form.set("file", file);
        form.set("chain_limit", String(limit));
        body = form;
      } else {
        body = JSON.stringify({ raw_email: raw, chain_limit: limit });
        headers = { "Content-Type": "application/json" };
      }
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers,
        body,
        signal: pending.signal,
        cache: "no-store",
      });
      const data = await response.json();
      if (id !== requestId.current) return;
      if (!response.ok)
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "输入无法分析，请检查文件和邮件头。",
        );
      if (
        data.schema_version !== "0.1" ||
        !Array.isArray(data.headers) ||
        !Array.isArray(data.route)
      )
        throw new Error("分析服务返回了不兼容的报告。");
      const next = data as MailReport;
      setReport(next);
      setSelected(next.route[0]?.header_id || next.headers[0]?.id || null);
      setDirty(false);
      setRevision((value) => value + 1);
    } catch (caught) {
      if (id === requestId.current && !pending.signal.aborted)
        setError(
          caught instanceof Error ? caught.message : "请求失败，请重试。",
        );
    } finally {
      if (id === requestId.current) setBusy(false);
    }
  }
  function download() {
    if (!report) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json;charset=utf-8",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `mailtrace-${report.source.input_sha256.slice(0, 12)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const field = report?.headers.find((header) => header.id === selected);
  const hop = report?.route.find((item) => item.header_id === selected);
  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="MailTrace 首页">
          <span className="brand-symbol">
            <Icon name="mail" size={23} />
          </span>
          <span>
            MailTrace<span className="brand-period">.</span>
          </span>
        </a>
        <div className="topbar-subtitle">MAIL HEADER INTELLIGENCE</div>
        <a className="lab-back" href="/lab">
          研究工作台 ↗
        </a>
        <span className="service-tag">
          <span className="status-dot" />
          本地工作台 <span className="version">v0.5</span>
        </span>
      </header>
      <div className="workbench-layout">
        <InputPanel
          raw={raw}
          file={file}
          busy={busy}
          error={error}
          limit={limit}
          onText={chooseText}
          onFile={chooseFile}
          onLimit={(value) => {
            invalidate();
            setLimit(value);
          }}
          onAnalyze={submit}
          onClear={clear}
          onError={setError}
        />
        <main className="report-workspace" aria-busy={busy}>
          <div className="workspace-heading">
            <div>
              <span className="section-eyebrow">
                THE INVESTIGATION WORKSPACE
              </span>
              <h1>循着邮件，找到线索。</h1>
            </div>
            <span className="workspace-mark">TRACE / INSPECT / UNDERSTAND</span>
          </div>
          {!report ? (
            <div className="welcome-panel">
              <div className="welcome-kicker">
                <span className="status-dot" />
                从原文，到可核查的证据
              </div>
              <h2>
                每一次传输，
                <br />
                都会留下痕迹。
              </h2>
              <p>
                还原邮件头中声明的路径，识别时间与字段异常，
                <br />
                让链路、认证和原文在同一处连接起来。
              </p>
              <div className="welcome-chain" aria-hidden="true">
                <div>
                  <Icon name="mail" size={25} />
                  <span>来源声明</span>
                </div>
                <span className="welcome-wire">SMTP →</span>
                <div>
                  <Icon name="layers" size={25} />
                  <span>中继节点</span>
                </div>
                <span className="welcome-wire">SMTP →</span>
                <div>
                  <Icon name="file" size={25} />
                  <span>原始证据</span>
                </div>
              </div>
              <div className="welcome-footer">
                <span>01 粘贴或上传</span>
                <span>02 分析声明路径</span>
                <span>03 回到原始字段</span>
              </div>
            </div>
          ) : (
            <>
              <section className="message-overview">
                <div className="message-title">
                  <span className="section-eyebrow">MESSAGE OVERVIEW</span>
                  <h2>{report.message.subject || "无主题"}</h2>
                  <div className="message-addresses">
                    <span>From</span>
                    <strong>
                      {report.message.from_addresses
                        .map((item) => item.address)
                        .join(", ") || "未知"}
                    </strong>
                    <span className="address-arrow">→</span>
                    <span>To</span>
                    <strong>
                      {report.message.to_addresses
                        .map((item) => item.address)
                        .join(", ") || "未知"}
                    </strong>
                  </div>
                </div>
                <button className="download-button" onClick={download}>
                  <Icon name="download" />
                  下载 JSON
                </button>
              </section>
              {dirty && (
                <div className="stale-banner" role="status">
                  输入已更改。下方为上一份分析结果，请重新分析以更新报告。
                </div>
              )}
              <div className="report-metrics">
                <div>
                  <span>传输跳数</span>
                  <strong>
                    {report.route.length}
                    <small>hops</small>
                  </strong>
                </div>
                <div>
                  <span>观测延迟</span>
                  <strong>
                    {report.route_summary.total_observed_delay_seconds ?? "—"}
                    <small>s</small>
                  </strong>
                </div>
                <div>
                  <span>调查提示</span>
                  <strong>
                    {report.warnings.length}
                    <small>findings</small>
                  </strong>
                </div>
                <div>
                  <span>原始字段</span>
                  <strong>
                    {report.headers.length}
                    <small>headers</small>
                  </strong>
                </div>
              </div>
              <div className="trace-grid">
                <TraceRoute
                  key={`route-${revision}`}
                  route={report.route}
                  selected={selected}
                  onSelect={select}
                />
                <EvidencePanel field={field} hop={hop} />
              </div>
              <ReportSections
                key={`details-${revision}`}
                report={report}
                onSelect={select}
              />
            </>
          )}
          <footer className="workspace-footer">
            <span>MailTrace · 让每条线索都有出处</span>
            <span>解析与调查工具 · 来源未经主动验证</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
