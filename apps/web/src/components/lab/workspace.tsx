"use client";
import { useEffect, useRef, useState } from "react";
import {
  labRequest,
  type CaseSpec,
  type Experiment,
  type SweepSpec,
} from "@/lib/lab";
import { Icon } from "../icons";
import { ForgePanel } from "./forge-panel";
import { CapturePanel } from "./capture-panel";
import { HistoryPanel } from "./history";
import { LabResults } from "./results";

type Mode = "forge" | "compare" | "history";
export function LabWorkspace() {
  const [mode, setMode] = useState<Mode>("forge");
  const [run, setRun] = useState<Experiment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const serial = useRef(0);
  useEffect(() => () => controller.current?.abort(), []);
  function cancel() {
    serial.current++;
    controller.current?.abort();
    setBusy(false);
    setNotice("已取消页面等待。后台可能继续归档；请刷新实验历史核查结果。");
  }
  function switchMode(next: Mode) {
    serial.current++;
    controller.current?.abort();
    setBusy(false);
    setError(null);
    setNotice(null);
    setMode(next);
  }
  async function execute(path: string, init: RequestInit = {}) {
    controller.current?.abort();
    const pending = new AbortController();
    controller.current = pending;
    const id = ++serial.current;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await labRequest<Experiment>(path, {
        ...init,
        signal: pending.signal,
      });
      if (id === serial.current) {
        setRun(result);
        setNotice("实验已保存。可下载原始数据，或从实验历史重新打开。");
      }
    } catch (error) {
      if (id === serial.current && !pending.signal.aborted)
        setError(error instanceof Error ? error.message : "实验操作失败。");
    } finally {
      if (id === serial.current) setBusy(false);
    }
  }
  function forge(body: { case: CaseSpec; sweep?: SweepSpec }) {
    void execute("forge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }
  return (
    <div className="app-shell lab-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="MailTrace 首页">
          <span className="brand-symbol">
            <Icon name="mail" size={23} />
          </span>
          <span>
            MailTrace<span className="brand-period">.</span>
          </span>
        </a>
        <span className="topbar-subtitle">RESEARCH NOTEBOOK</span>
        <a className="lab-back" href="/">
          单封分析 ↗
        </a>
        <span className="service-tag">
          <span className="status-dot" />
          本地实验归档 <span className="version">v0.5</span>
        </span>
      </header>
      <nav className="lab-navigation" aria-label="研究工具">
        <a href="/">单封分析</a>
        <button
          type="button"
          aria-current={mode === "forge" ? "page" : undefined}
          onClick={() => switchMode("forge")}
        >
          <Icon name="layers" />
          样本生成
        </button>
        <button
          type="button"
          aria-current={mode === "compare" ? "page" : undefined}
          onClick={() => switchMode("compare")}
        >
          <Icon name="route" />
          逐跳对比
        </button>
        <button
          type="button"
          aria-current={mode === "history" ? "page" : undefined}
          onClick={() => switchMode("history")}
        >
          <Icon name="clock" />
          实验历史
        </button>
      </nav>
      <div className={`lab-layout ${mode === "history" ? "history-mode" : ""}`}>
        {mode !== "history" && (
          <aside className="lab-sidebar">
            {mode === "forge" ? (
              <ForgePanel busy={busy} onSubmit={forge} onError={setError} />
            ) : (
              <CapturePanel
                busy={busy}
                onSubmit={(body) =>
                  void execute("compare", { method: "POST", body })
                }
                onError={setError}
              />
            )}
            <p className="lab-storage-note">
              <Icon name="file" />
              研究操作会自动保存原始邮件、参数和报告到本地实验目录。单封分析仍不保存历史。
            </p>
          </aside>
        )}
        <main className="lab-workspace" aria-busy={busy}>
          <div className="workspace-heading">
            <div>
              <span className="section-eyebrow">
                REPRODUCE / OBSERVE / COMPARE
              </span>
              <h1>让实验有据可循。</h1>
            </div>
            <span className="workspace-mark">MAILTRACE LAB / 0.1</span>
          </div>
          {busy && (
            <div className="lab-pending" role="status">
              <span>正在处理与保存实验…</span>
              <button type="button" className="text-button" onClick={cancel}>
                取消等待
              </button>
            </div>
          )}
          {error && (
            <div className="error-box" role="alert">
              <Icon name="alert" />
              {error}
            </div>
          )}
          {notice && (
            <p className="lab-notice" role="status">
              {notice}
            </p>
          )}
          {mode === "history" && (
            <HistoryPanel onOpen={(id) => void execute(`runs/${id}`)} />
          )}
          {run ? (
            <LabResults
              key={run.id}
              run={run}
              busy={busy}
              onReproduce={() =>
                void execute(`runs/${run.id}/reproduce`, { method: "POST" })
              }
            />
          ) : (
            mode !== "history" && (
              <section className="lab-welcome">
                <span className="section-eyebrow">
                  A REPRODUCIBLE EXPERIMENT STARTS HERE
                </span>
                <h2>
                  一个参数。
                  <br />
                  一组样本。
                  <br />
                  <em>每一次变化都有证据。</em>
                </h2>
                <p>
                  从 Received 数量、行长与头区大小开始。
                  <br />
                  保留畸形字段和重复实例，比较观测点之间真正发生的变化。
                </p>
                <div className="lab-process">
                  <span>
                    <b>01</b>生成样本
                  </span>
                  <i>→</i>
                  <span>
                    <b>02</b>导入采集
                  </span>
                  <i>→</i>
                  <span>
                    <b>03</b>对比证据
                  </span>
                </div>
                <div className="lab-welcome-bottom">
                  <strong>本轮离线研究</strong>
                  <span>
                    不自动发送邮件 · 不推断 MTA 极限 · 原始实验自动归档
                  </span>
                </div>
              </section>
            )
          )}
          <footer className="workspace-footer">
            <span>MailTrace · 参数与证据一起保存</span>
            <span>HeaderDiff 描述变化 · 现有规则提供调查提示</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
