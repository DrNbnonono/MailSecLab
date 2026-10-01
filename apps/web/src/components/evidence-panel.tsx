"use client";
import { delay, utc, type HeaderField, type MailHop } from "@/lib/report";
import { Icon } from "./icons";

export function EvidencePanel({
  field,
  hop,
  id = "evidence-panel",
}: {
  field: HeaderField | undefined;
  hop: MailHop | undefined;
  id?: string;
}) {
  return (
    <aside
      className="panel evidence-panel"
      id={id}
      tabIndex={-1}
      aria-label="原始证据详情"
    >
      <div className="panel-heading">
        <div>
          <span className="section-eyebrow">03 / EVIDENCE</span>
          <h2>原始证据</h2>
        </div>
        <Icon name="file" />
      </div>
      {!field ? (
        <div className="small-empty evidence-empty">
          <Icon name="search" size={30} />
          <p>每一个结论，都回到原文。</p>
          <span>
            选择一条链路、认证结果或提示，
            <br />
            查看对应字段与字节位置。
          </span>
        </div>
      ) : (
        <div className="evidence-content">
          <div className="evidence-title">
            <strong>{field.name || "畸形字段"}</strong>
            <span className={`pill ${field.recognized ? "teal" : "amber"}`}>
              {field.recognized ? "已识别" : "未被解析器识别"}
            </span>
          </div>
          <div className="evidence-meta mono">
            <span>{field.id}</span>
            <span>
              L{field.start_line}–{field.end_line}
            </span>
            <span>
              bytes {field.start_byte}–{field.end_byte}
            </span>
          </div>
          <pre className="raw-evidence">{field.raw.slice(0, 65_536)}</pre>
          {field.raw.length > 65_536 && (
            <p className="limit-note">
              展示前 64 KiB 字符，完整字节见下载的 JSON。
            </p>
          )}
          {hop && (
            <dl className="hop-details">
              <div>
                <dt>协议</dt>
                <dd>{hop.protocol || "未知"}</dd>
              </div>
              <div>
                <dt>队列 ID</dt>
                <dd>{hop.queue_id || "未声明"}</dd>
              </div>
              <div>
                <dt>收件人</dt>
                <dd>{hop.recipient || "未声明"}</dd>
              </div>
              <div>
                <dt>时间（UTC）</dt>
                <dd>{utc(hop.timestamp)}</dd>
              </div>
              <div>
                <dt>原始日期</dt>
                <dd>{hop.timestamp_raw || "未声明"}</dd>
              </div>
              <div>
                <dt>相邻延迟</dt>
                <dd
                  className={
                    hop.delay_seconds !== null && hop.delay_seconds < 0
                      ? "negative"
                      : ""
                  }
                >
                  {delay(hop.delay_seconds)}
                </dd>
              </div>
              <div>
                <dt>来源 IP</dt>
                <dd>
                  {hop.from.ip ||
                    (hop.from.ip_candidates.length
                      ? hop.from.ip_candidates.join(", ")
                      : "未声明")}
                </dd>
              </div>
              <div>
                <dt>解析状态</dt>
                <dd>{hop.parse_status}</dd>
              </div>
            </dl>
          )}
          <p className="evidence-footnote">
            展示文本用于阅读。JSON 中的头区 Base64 与字节偏移保留原始证据。
          </p>
        </div>
      )}
    </aside>
  );
}
