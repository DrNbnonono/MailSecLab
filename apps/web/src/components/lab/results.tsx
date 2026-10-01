"use client";
import { useEffect, useState } from "react";
import {
  changeNames,
  kindNames,
  labRequest,
  labUrl,
  type Difference,
  type EvidenceRef,
  type Experiment,
} from "@/lib/lab";
import type { MailReport } from "@/lib/report";
import { EvidencePanel } from "../evidence-panel";
import { TraceRoute } from "../trace-route";
import { ReportSections } from "../report-sections";

function EvidenceChoices({
  references,
  onSelect,
}: {
  references: EvidenceRef[];
  onSelect: (ref: EvidenceRef) => void;
}) {
  const [page, setPage] = useState(0);
  return (
    <>
      <div className="lab-evidence-choices">
        {references.slice(page * 50, page * 50 + 50).map((ref) => (
          <button
            type="button"
            className="text-button"
            key={ref.header_id}
            onClick={() => onSelect(ref)}
          >
            {ref.header_id} ↗
          </button>
        ))}
      </div>
      {references.length > 50 && (
        <div className="pagination">
          <button
            type="button"
            disabled={!page}
            onClick={() => setPage(page - 1)}
          >
            前 50 项
          </button>
          <span>
            {page + 1} / {Math.ceil(references.length / 50)} 页 ·{" "}
            {references.length} 候选
          </span>
          <button
            type="button"
            disabled={(page + 1) * 50 >= references.length}
            onClick={() => setPage(page + 1)}
          >
            后 50 项
          </button>
        </div>
      )}
    </>
  );
}

function FieldEvidence({
  report,
  reference,
  id,
}: {
  report: MailReport | null;
  reference: EvidenceRef | undefined;
  id: string;
}) {
  const field = report?.headers.find(
    (item) => item.id === reference?.header_id,
  );
  const hop = report?.route.find(
    (item) => item.header_id === reference?.header_id,
  );
  return (
    <div>
      {reference && (
        <p className="lab-reference mono">
          {reference.snapshot_id} / {reference.header_id}
          <br />
          SHA-256 {reference.sha256}
        </p>
      )}
      {!reference && (
        <p className="lab-form-note">此侧没有已指定的对应字段实例。</p>
      )}
      <EvidencePanel field={field} hop={hop} id={id} />
    </div>
  );
}

export function LabResults({
  run,
  busy,
  onReproduce,
}: {
  run: Experiment;
  busy: boolean;
  onReproduce: () => void;
}) {
  const [snapshot, setSnapshot] = useState(run.snapshots[0].id);
  const [diffId, setDiffId] = useState(run.diffs[0]?.id || "");
  const [view, setView] = useState<"snapshot" | "diff">(
    run.diffs.length ? "diff" : "snapshot",
  );
  const [reports, setReports] = useState<MailReport[]>([]);
  const [difference, setDifference] = useState<Difference | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [changeId, setChangeId] = useState<string | null>(null);
  const [beforeRef, setBeforeRef] = useState<EvidenceRef | undefined>();
  const [afterRef, setAfterRef] = useState<EvidenceRef | undefined>();
  const [page, setPage] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setReports([]);
    setDifference(null);
    setPage(0);
    const signal = controller.signal;
    async function load() {
      try {
        if (view === "snapshot") {
          const report = await labRequest<MailReport>(
            `runs/${run.id}/snapshots/${snapshot}/report`,
            { signal },
          );
          if (signal.aborted) return;
          setReports([report]);
          setSelected(
            report.route[0]?.header_id || report.headers[0]?.id || null,
          );
        } else {
          const diff = await labRequest<Difference>(
            `runs/${run.id}/diffs/${diffId}`,
            { signal },
          );
          const [left, right] = await Promise.all([
            labRequest<MailReport>(
              `runs/${run.id}/snapshots/${diff.before_id}/report`,
              { signal },
            ),
            labRequest<MailReport>(
              `runs/${run.id}/snapshots/${diff.after_id}/report`,
              { signal },
            ),
          ]);
          if (signal.aborted) return;
          setDifference(diff);
          setReports([left, right]);
          const first = diff.changes[0];
          setChangeId(first?.id || null);
          setBeforeRef(first?.before[0]);
          setAfterRef(first?.after[0]);
        }
      } catch (error) {
        if (!signal.aborted)
          setError(error instanceof Error ? error.message : "证据读取失败。");
      } finally {
        if (!signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [run.id, snapshot, diffId, view]);
  const selectedChange = difference?.changes.find(
    (item) => item.id === changeId,
  );
  const selectedSnapshot = run.snapshots.find((item) => item.id === snapshot)!;
  const snapshotReport = reports[0];
  function selectHeader(id: string) {
    setSelected(id);
    if (window.innerWidth < 1100)
      document
        .getElementById("lab-snapshot-evidence")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  return (
    <div className="lab-results">
      <section className="lab-run-heading">
        <div>
          <span className="section-eyebrow">SAVED RESEARCH EXPERIMENT</span>
          <h2>{run.name}</h2>
          <p>
            <span className="pill teal">{kindNames[run.kind]}</span>
            <span>{new Date(run.created_at).toLocaleString()}</span>
          </p>
          <code>{run.id}</code>
          {run.derived_from && (
            <p className="lab-form-note">复现自 {run.derived_from}</p>
          )}
        </div>
        <div className="lab-export-actions">
          <a
            className="download-button"
            href={labUrl(`runs/${run.id}/export/zip`)}
          >
            下载实验 ZIP
          </a>
          <a
            className="download-button"
            href={labUrl(`runs/${run.id}/export/csv`)}
          >
            指标 CSV
          </a>
          <a
            className="text-button"
            href={labUrl(`runs/${run.id}`)}
            download={`manifest-${run.id}.json`}
          >
            清单 JSON
          </a>
          <button
            type="button"
            className="text-button"
            disabled={busy}
            onClick={onReproduce}
          >
            核验并复现为新实验 ↗
          </button>
        </div>
      </section>
      <div className="lab-observation-note">
        <strong>原始实验邮件已自动保存到本地。</strong>
        <span>
          {run.kind === "capture_sequence"
            ? "差分记录观测点之间的变化，不确定修改者。"
            : "参数扫描组不代表传输链；SMTP 接受/拒绝状态尚未测量。"}
        </span>
      </div>
      <section className="panel lab-metrics-panel">
        <div className="panel-heading">
          <h2>样本与实测指标</h2>
          <span className="count">{run.snapshots.length} snapshots</span>
        </div>
        <div className="lab-table-scroll">
          <table className="lab-metrics-table">
            <thead>
              <tr>
                <th>快照 / 采集标签</th>
                <th>
                  Received
                  <br />
                  候选 / 识别
                </th>
                <th>头区 bytes</th>
                <th>最长行 bytes</th>
                <th>邮件 bytes</th>
                <th>证据</th>
              </tr>
            </thead>
            <tbody>
              {run.snapshots.map((item) => (
                <tr
                  key={item.id}
                  className={
                    snapshot === item.id && view === "snapshot" ? "active" : ""
                  }
                >
                  <td>
                    <strong>{item.label}</strong>
                    <small>
                      {item.id}
                      {item.mta ? ` · ${item.mta}` : ""}
                      {item.case && run.sweep
                        ? ` · ${run.sweep.axis}=${item.case[run.sweep.axis]}`
                        : ""}
                    </small>
                  </td>
                  <td>
                    {item.metrics.candidate_received_count} /{" "}
                    {item.metrics.recognized_received_count}
                  </td>
                  <td>{item.metrics.header_bytes.toLocaleString()}</td>
                  <td>{item.metrics.max_line_bytes.toLocaleString()}</td>
                  <td>{item.metrics.input_bytes.toLocaleString()}</td>
                  <td>
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => {
                        setSnapshot(item.id);
                        setView("snapshot");
                      }}
                    >
                      分析快照
                    </button>
                    <a
                      className="text-button"
                      href={labUrl(
                        `runs/${run.id}/snapshots/${item.id}/message`,
                      )}
                    >
                      原始 .eml ↓
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {run.diffs.length > 0 && (
        <div className="lab-comparison-controls">
          <button
            className="download-button"
            type="button"
            onClick={() => setView("diff")}
          >
            相邻快照差分
          </button>
          <label>
            观测区间
            <select
              aria-label="选择相邻观测区间"
              value={diffId}
              onChange={(event) => {
                setDiffId(event.target.value);
                setView("diff");
              }}
            >
              {run.diffs.map((item) => (
                <option key={item.id} value={item.id}>
                  {run.snapshots.find((s) => s.id === item.before_id)?.label} →{" "}
                  {run.snapshots.find((s) => s.id === item.after_id)?.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
      {loading && (
        <p className="lab-loading" role="status">
          <span className="spinner" />
          正在核验与读取证据…
        </p>
      )}
      {error && (
        <div className="error-box" role="alert">
          {error}
        </div>
      )}
      {!loading && !error && view === "snapshot" && snapshotReport && (
        <>
          <div className="lab-section-heading">
            <span className="section-eyebrow">SNAPSHOT ANALYSIS</span>
            <h3>{selectedSnapshot.label}</h3>
            <p>邮件头声明与现有启发式提示；不代表传输成功或可信来源。</p>
          </div>
          <div className="trace-grid">
            <TraceRoute
              key={`${run.id}-${snapshot}`}
              route={snapshotReport.route}
              selected={selected}
              onSelect={selectHeader}
            />
            <EvidencePanel
              id="lab-snapshot-evidence"
              field={snapshotReport.headers.find(
                (item) => item.id === selected,
              )}
              hop={snapshotReport.route.find(
                (item) => item.header_id === selected,
              )}
            />
          </div>
          <ReportSections
            key={`${run.id}-${snapshot}`}
            report={snapshotReport}
            onSelect={selectHeader}
          />
        </>
      )}
      {!loading && !error && view === "diff" && difference && (
        <>
          <div className="lab-diff-summary">
            {Object.entries(difference.summary).map(([kind, count]) => (
              <div key={kind}>
                <span>{changeNames[kind]}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
          <p className="lab-form-note">
            {difference.conclusion}
            {difference.capture_gap &&
              " 已标记采集缺口；此区间可能跨越多个处理节点。"}
          </p>
          <div className="lab-diff-grid">
            <section className="panel lab-change-list">
              <div className="panel-heading">
                <h2>字段变化</h2>
                <span className="count">
                  {difference.changes.length} observations
                </span>
              </div>
              {!difference.changes.length && (
                <p className="empty-note">两份邮件的头区没有变化。</p>
              )}
              {difference.changes
                .slice(page * 50, page * 50 + 50)
                .map((item) => (
                  <button
                    type="button"
                    className={`lab-change ${changeId === item.id ? "active" : ""}`}
                    key={item.id}
                    onClick={() => {
                      setChangeId(item.id);
                      setBeforeRef(item.before[0]);
                      setAfterRef(item.after[0]);
                    }}
                  >
                    <span className={`change-symbol ${item.kind}`}>
                      {item.kind === "added"
                        ? "+"
                        : item.kind === "removed"
                          ? "−"
                          : item.kind === "ambiguous"
                            ? "?"
                            : "~"}
                    </span>
                    <span>
                      <strong>
                        {item.after[0]?.name ||
                          item.before[0]?.name ||
                          "畸形候选"}
                      </strong>
                      <small>
                        {changeNames[item.kind]} · {item.before.length} →{" "}
                        {item.after.length}
                      </small>
                    </span>
                    <span>↗</span>
                  </button>
                ))}
              {difference.changes.length > 50 && (
                <div className="pagination">
                  <button
                    type="button"
                    disabled={!page}
                    onClick={() => setPage(page - 1)}
                  >
                    上一页
                  </button>
                  <span>
                    {page + 1} / {Math.ceil(difference.changes.length / 50)}
                  </span>
                  <button
                    type="button"
                    disabled={(page + 1) * 50 >= difference.changes.length}
                    onClick={() => setPage(page + 1)}
                  >
                    下一页
                  </button>
                </div>
              )}
            </section>
            <div className="lab-diff-detail">
              {selectedChange && (
                <div className="panel lab-change-notes">
                  <span className="section-eyebrow">
                    {changeNames[selectedChange.kind]} / {selectedChange.id}
                  </span>
                  {selectedChange.notes.map((note, i) => (
                    <p key={i}>{note}</p>
                  ))}
                  {!!Object.keys(selectedChange.received_changes).length && (
                    <details open>
                      <summary>Received 结构化变化</summary>
                      <pre>
                        {JSON.stringify(
                          selectedChange.received_changes,
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  )}
                </div>
              )}
              <div className="lab-two-evidence">
                <section>
                  <h3>之前 · {difference.before_id}</h3>
                  <EvidenceChoices
                    key={`before-${changeId}`}
                    references={selectedChange?.before || []}
                    onSelect={setBeforeRef}
                  />
                  <FieldEvidence
                    report={reports[0] || null}
                    reference={beforeRef}
                    id="lab-diff-before"
                  />
                </section>
                <section>
                  <h3>之后 · {difference.after_id}</h3>
                  <EvidenceChoices
                    key={`after-${changeId}`}
                    references={selectedChange?.after || []}
                    onSelect={setAfterRef}
                  />
                  <FieldEvidence
                    report={reports[1] || null}
                    reference={afterRef}
                    id="lab-diff-after"
                  />
                </section>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
