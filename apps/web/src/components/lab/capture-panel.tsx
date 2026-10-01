"use client";
import { useRef, useState } from "react";
import { Icon } from "../icons";

interface Capture {
  key: string;
  file: File;
  label: string;
  capture_point: string;
  mta: string;
  mta_version: string;
  config_digest: string;
  captured_at: string;
  capture_gap: boolean;
}
export function CapturePanel({
  busy,
  onSubmit,
  onError,
}: {
  busy: boolean;
  onSubmit: (form: FormData) => void;
  onError: (message: string) => void;
}) {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  function append(files: File[]) {
    if (captures.length + files.length > 20) {
      onError("一次最多 20 份快照。");
      return;
    }
    if (
      files.some(
        (file) =>
          !file.name.toLowerCase().endsWith(".eml") ||
          file.size === 0 ||
          file.size > 10 * 1024 * 1024,
      )
    ) {
      onError("请选择非空 .eml 文件，每封最多 10 MiB。");
      return;
    }
    if (
      [...captures.map((item) => item.file), ...files].reduce(
        (sum, file) => sum + file.size,
        0,
      ) >
      50 * 1024 * 1024
    ) {
      onError("快照累计超过 50 MiB。");
      return;
    }
    setCaptures((previous) => [
      ...previous,
      ...files.map((file) => ({
        key: crypto.randomUUID(),
        file,
        label: file.name,
        capture_point: "unknown",
        mta: "",
        mta_version: "",
        config_digest: "",
        captured_at: "",
        capture_gap: false,
      })),
    ]);
  }
  function update(key: string, patch: Partial<Capture>) {
    setCaptures((previous) =>
      previous.map((item) => (item.key === key ? { ...item, ...patch } : item)),
    );
  }
  function move(index: number, direction: number) {
    setCaptures((previous) => {
      const next = [...previous];
      [next[index], next[index + direction]] = [
        next[index + direction],
        next[index],
      ];
      return next;
    });
  }
  function submit() {
    const form = new FormData();
    for (const item of captures) form.append("files", item.file);
    form.set(
      "metadata",
      JSON.stringify(
        captures.map(({ file, key, ...entry }) => ({
          ...entry,
          mta: entry.mta || null,
          mta_version: entry.mta_version || null,
          config_digest: entry.config_digest || null,
          captured_at: entry.captured_at || null,
        })),
      ),
    );
    onSubmit(form);
  }
  return (
    <div className="lab-input">
      <span className="section-eyebrow">01 / CAPTURE SEQUENCE</span>
      <h2>保留每一处观测。</h2>
      <p className="lab-input-intro">
        导入原始采集邮件，明确排列先后。采集点之间的变化，不自动归因到某台 MTA。
      </p>
      <fieldset disabled={busy}>
        <button
          type="button"
          className={`dropzone ${dragging ? "dragging" : ""}`}
          onClick={() => input.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            if (!busy) append(Array.from(event.dataTransfer.files));
          }}
        >
          <Icon name="upload" size={25} />
          <strong>添加逐跳 .eml 快照</strong>
          <span>点击或拖入 · 2–20 份 · 累计 50 MiB</span>
        </button>
        <input
          ref={input}
          type="file"
          className="sr-only"
          aria-label="选择逐跳快照"
          accept=".eml"
          multiple
          onChange={(event) => {
            append(Array.from(event.target.files || []));
            event.target.value = "";
          }}
        />
        <div className="capture-list">
          {captures.map((item, index) => (
            <article className="capture-row" key={item.key}>
              <div className="capture-heading">
                <span className="capture-number">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <strong title={item.file.name}>{item.file.name}</strong>
                <div className="capture-actions">
                  <button
                    type="button"
                    aria-label={`上移快照 ${index + 1}`}
                    disabled={index === 0}
                    onClick={() => move(index, -1)}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    aria-label={`下移快照 ${index + 1}`}
                    disabled={index === captures.length - 1}
                    onClick={() => move(index, 1)}
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    aria-label={`移除快照 ${index + 1}`}
                    onClick={() =>
                      setCaptures((previous) =>
                        previous.filter((entry) => entry.key !== item.key),
                      )
                    }
                  >
                    ×
                  </button>
                </div>
              </div>
              <label className="lab-field">
                采集标签 {index + 1}
                <input
                  value={item.label}
                  onChange={(event) =>
                    update(item.key, { label: event.target.value })
                  }
                />
              </label>
              <div className="lab-form-grid">
                <label className="lab-field">
                  采集位置 {index + 1}
                  <select
                    value={item.capture_point}
                    onChange={(event) =>
                      update(item.key, { capture_point: event.target.value })
                    }
                  >
                    <option value="unknown">未知</option>
                    <option value="submitted">提交端</option>
                    <option value="ingress">MTA 入站</option>
                    <option value="egress">MTA 出站</option>
                    <option value="delivered">最终交付</option>
                  </select>
                </label>
                <label className="lab-field">
                  MTA 名称 {index + 1}
                  <input
                    placeholder="可选"
                    value={item.mta}
                    onChange={(event) =>
                      update(item.key, { mta: event.target.value })
                    }
                  />
                </label>
              </div>
              <details className="lab-advanced">
                <summary>版本、配置与采集时间</summary>
                <label className="lab-field">
                  MTA 版本 {index + 1}
                  <input
                    value={item.mta_version}
                    onChange={(event) =>
                      update(item.key, { mta_version: event.target.value })
                    }
                  />
                </label>
                <label className="lab-field">
                  配置摘要 {index + 1}
                  <input
                    value={item.config_digest}
                    onChange={(event) =>
                      update(item.key, { config_digest: event.target.value })
                    }
                  />
                </label>
                <label className="lab-field">
                  采集时间 {index + 1}
                  <input
                    placeholder="ISO 时间，含时区；可留空"
                    value={item.captured_at}
                    onChange={(event) =>
                      update(item.key, { captured_at: event.target.value })
                    }
                  />
                </label>
              </details>
              {index > 0 && (
                <label className="lab-check">
                  <input
                    type="checkbox"
                    checked={item.capture_gap}
                    onChange={(event) =>
                      update(item.key, { capture_gap: event.target.checked })
                    }
                  />
                  与前一快照之间存在采集缺口
                </label>
              )}
            </article>
          ))}
        </div>
        {!captures.length && (
          <p className="lab-form-note">
            文件保持原始字节；排序以你的设置为准，不从邮件日期推断。
          </p>
        )}
        <button
          type="button"
          className="analyze-button"
          disabled={captures.length < 2}
          onClick={submit}
        >
          {busy ? (
            <>
              <span className="spinner" />
              正在比较与归档
            </>
          ) : (
            "比较并保存实验 →"
          )}
        </button>
        <button
          type="button"
          className="text-button lab-reset"
          onClick={() => setCaptures([])}
        >
          清空快照列表
        </button>
      </fieldset>
    </div>
  );
}
