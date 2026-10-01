"use client";
import { useEffect, useRef, useState } from "react";
import {
  kindNames,
  labRequest,
  type HistoryItem,
  type HistoryPage,
} from "@/lib/lab";

export function HistoryPanel({ onOpen }: { onOpen: (id: string) => void }) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  async function load(next: string | null = null) {
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setError(null);
    try {
      const page = await labRequest<HistoryPage>(
        `runs${next ? `?cursor=${next}` : ""}`,
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      setItems((previous) =>
        next ? [...previous, ...page.items] : page.items,
      );
      setCursor(page.next_cursor);
    } catch (error) {
      if (!controller.signal.aborted)
        setError(error instanceof Error ? error.message : "历史读取失败。");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  useEffect(() => {
    void load();
    return () => pending.current?.abort();
  }, []);
  return (
    <section className="lab-history">
      <div className="lab-history-heading">
        <div>
          <span className="section-eyebrow">LOCAL EXPERIMENT ARCHIVE</span>
          <h2>可以重新打开的证据。</h2>
          <p>每次研究操作保存为独立实验，原始邮件与参数不会被后续实验覆盖。</p>
        </div>
        <button
          type="button"
          className="download-button"
          disabled={busy}
          onClick={() => void load()}
        >
          刷新历史
        </button>
      </div>
      {error && (
        <p className="error-box" role="alert">
          {error}
        </p>
      )}
      {!items.length && !busy && !error && (
        <div className="lab-empty-history">
          还没有保存的研究实验。先生成一组样本，或导入逐跳采集。
        </div>
      )}
      <div className="history-grid">
        {items.map((item) => (
          <button
            type="button"
            key={item.id}
            className={`history-card ${item.integrity === "failed" ? "corrupt" : ""}`}
            onClick={() => onOpen(item.id)}
          >
            <div>
              <span className="pill subtle">
                {kindNames[item.kind] || "无法核验"}
              </span>
              <span>↗</span>
            </div>
            <h3>{item.name}</h3>
            <p>
              {item.snapshot_count ?? "—"} 份快照 ·{" "}
              {item.created_at
                ? new Date(item.created_at).toLocaleString()
                : "清单损坏"}
            </p>
            <code>{item.id}</code>
            {item.integrity === "failed" && (
              <strong>完整性异常；打开时显示核验结果</strong>
            )}
          </button>
        ))}
      </div>
      {busy && (
        <p className="lab-form-note" role="status">
          正在读取本地归档…
        </p>
      )}
      {cursor && (
        <button
          type="button"
          className="download-button"
          disabled={busy}
          onClick={() => void load(cursor)}
        >
          加载下一页
        </button>
      )}
    </section>
  );
}
