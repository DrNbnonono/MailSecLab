"use client";
import { useRef, useState } from "react";
import { Icon } from "./icons";
import { BASIC_SAMPLE, LOOP_SAMPLE } from "@/lib/samples";

interface Props {
  raw: string;
  file: File | null;
  busy: boolean;
  error: string | null;
  limit: number;
  onText: (value: string) => void;
  onFile: (file: File | null) => void;
  onLimit: (limit: number) => void;
  onAnalyze: () => void;
  onClear: () => void;
  onError: (message: string) => void;
}

export function InputPanel(props: Props) {
  const input = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  function accept(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".eml")) {
      props.onError("请选择 .eml 邮件文件。");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      props.onError("文件超过 10 MiB 上限。");
      return;
    }
    props.onFile(file);
    if (input.current) input.current.value = "";
  }
  return (
    <aside className="input-panel">
      <div className="section-eyebrow">
        <span>01 / INPUT</span>
        <span className="pill subtle">仅本地分析</span>
      </div>
      <h2>一封邮件的起点。</h2>
      <p className="input-intro">
        粘贴原始邮件头，或导入一封邮件。
        <br />
        从传输路径开始，核查每一处声明。
      </p>
      <div className="field-heading">
        <label htmlFor="raw-email">原始邮件 / 邮件头</label>
        {props.raw && (
          <span>
            {new TextEncoder().encode(props.raw).length.toLocaleString()} bytes
          </span>
        )}
      </div>
      <textarea
        id="raw-email"
        spellCheck={false}
        value={props.raw}
        disabled={!!props.file}
        onChange={(event) => props.onText(event.target.value)}
        placeholder={
          "Received: from …\n    by … with ESMTPS; …\nAuthentication-Results: …\nFrom: …\nTo: …\nSubject: …"
        }
      />
      <div className="input-divider">
        <span />
        或上传原始文件
        <span />
      </div>
      <button
        type="button"
        className={`dropzone ${drag ? "dragging" : ""} ${props.file ? "has-file" : ""}`}
        onClick={() => input.current?.click()}
        onDragOver={(event) => {
          event.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDrag(false);
          accept(event.dataTransfer.files[0]);
        }}
      >
        <Icon name={props.file ? "file" : "upload"} size={24} />
        <strong>{props.file?.name || "拖入 .eml 文件"}</strong>
        <span>
          {props.file
            ? `${props.file.size.toLocaleString()} bytes · 按原字节解析`
            : "或点击选择文件 · 最大 10 MiB"}
        </span>
      </button>
      <input
        ref={input}
        className="sr-only"
        type="file"
        accept=".eml,message/rfc822"
        aria-label="选择邮件文件"
        onChange={(event) => accept(event.target.files?.[0])}
      />
      {props.file && (
        <button
          className="text-button file-remove"
          onClick={() => props.onFile(null)}
        >
          移除文件，改用文本
        </button>
      )}
      <details className="options">
        <summary>
          分析选项 <span>+</span>
        </summary>
        <label htmlFor="chain-limit">
          链长提示阈值{" "}
          <input
            id="chain-limit"
            type="number"
            min="1"
            step="1"
            value={Number.isFinite(props.limit) ? props.limit : ""}
            onChange={(event) => props.onLimit(Number(event.target.value))}
          />
        </label>
        <p>可配置的调查阈值，非协议限制。</p>
      </details>
      {props.error && (
        <div className="error-box" role="alert">
          <Icon name="alert" />
          <span>{props.error}</span>
        </div>
      )}
      <button
        className="analyze-button"
        onClick={props.onAnalyze}
        disabled={props.busy || (!props.raw.trim() && !props.file)}
      >
        {props.busy ? (
          <>
            <span className="spinner" />
            正在分析…
          </>
        ) : (
          <>
            分析邮件头 <Icon name="arrow" />
          </>
        )}
      </button>
      <div className="sample-heading">
        <span>先试试一封合成邮件</span>
        <button className="text-button" onClick={props.onClear}>
          清空
        </button>
      </div>
      <div className="samples">
        <button onClick={() => props.onText(BASIC_SAMPLE)}>
          <Icon name="route" />
          正常两跳<span>↗</span>
        </button>
        <button onClick={() => props.onText(LOOP_SAMPLE)}>
          <Icon name="alert" />
          可疑回返<span>↗</span>
        </button>
      </div>
      <div className="privacy-note">
        <span className="status-dot" />
        <p>
          邮件内容只用于当前分析。
          <br />
          不保存历史，不进行 DNS 查询。
        </p>
      </div>
    </aside>
  );
}
