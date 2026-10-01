"use client";
import { useState } from "react";
import type { CaseSpec, HeaderSpec, SweepSpec } from "@/lib/lab";

const initialHeaders: HeaderSpec[] = [
  { name: "From", value: "Alice <alice@sender.example>" },
  { name: "To", value: "Bob <bob@recipient.example>" },
  { name: "Subject", value: "MailTrace synthetic experiment" },
  { name: "Date", value: "Thu, 01 Oct 2026 12:00:00 +0000" },
  { name: "Message-ID", value: "<baseline@sender.example>" },
];

export function ForgePanel({
  busy,
  onSubmit,
  onError,
}: {
  busy: boolean;
  onSubmit: (body: { case: CaseSpec; sweep?: SweepSpec }) => void;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState("Received 增长实验");
  const [purpose, setPurpose] =
    useState("控制单一参数，比较邮件头解析与变化。");
  const [count, setCount] = useState("2");
  const [seed, setSeed] = useState("0");
  const [time, setTime] = useState("2026-10-01T12:00:00Z");
  const [topology, setTopology] = useState<"chain" | "return">("chain");
  const [folding, setFolding] = useState<"none" | "space" | "tab">("none");
  const [newline, setNewline] = useState<"crlf" | "lf">("crlf");
  const [date, setDate] = useState<
    "valid" | "backwards" | "invalid" | "unknown_timezone"
  >("valid");
  const [position, setPosition] = useState<"first" | "last">("first");
  const [colon, setColon] = useState(false);
  const [line, setLine] = useState("");
  const [headerSize, setHeaderSize] = useState("");
  const [headers, setHeaders] = useState(
    JSON.stringify(initialHeaders, null, 2),
  );
  const [batch, setBatch] = useState(false);
  const [axis, setAxis] = useState<SweepSpec["axis"]>("received_count");
  const [values, setValues] = useState("10, 20, 50, 100, 200");
  function submit() {
    try {
      if (!count.trim() || !seed.trim()) throw new Error("请填写数量与种子。");
      const ordered = JSON.parse(headers);
      if (!Array.isArray(ordered)) throw new Error("字段须为有序 JSON 列表。");
      const spec: CaseSpec = {
        name,
        purpose,
        seed: Number(seed),
        base_time: time,
        received_count: Number(count),
        topology,
        folding,
        newline,
        date_profile: date,
        received_position: position,
        pre_colon_space: colon,
        headers: ordered,
        max_line_bytes: line.trim() ? Number(line) : null,
        header_bytes: headerSize.trim() ? Number(headerSize) : null,
      };
      let sweep: SweepSpec | undefined;
      if (batch) {
        const parsed = values
          .split(/[,，\s]+/)
          .filter(Boolean)
          .map(Number);
        if (
          !parsed.length ||
          parsed.length > 20 ||
          parsed.some((value) => !Number.isInteger(value))
        )
          throw new Error("扫描值须为 1–20 个整数，以逗号或空白分隔。");
        sweep = { axis, values: parsed };
      }
      onSubmit({ case: spec, sweep });
    } catch (error) {
      onError(
        error instanceof SyntaxError
          ? "有序字段 JSON 无效，请检查引号和逗号。"
          : error instanceof Error
            ? error.message
            : "参数无效。",
      );
    }
  }
  function duplicate(fieldName: string) {
    try {
      const list = JSON.parse(headers);
      if (!Array.isArray(list)) throw new Error();
      list.push({
        name: fieldName,
        value:
          fieldName === "From"
            ? "Other <other@sender.example>"
            : "<duplicate@sender.example>",
      });
      setHeaders(JSON.stringify(list, null, 2));
    } catch {
      onError("请先修正有序字段 JSON。");
    }
  }
  return (
    <div className="lab-input">
      <span className="section-eyebrow">01 / MAILFORGE</span>
      <h2>把边界变成样本。</h2>
      <p className="lab-input-intro">
        精确控制原始字节，保存每一个参数。生成不代表 MTA 已接受。
      </p>
      <fieldset disabled={busy}>
        <label className="lab-field">
          实验名称
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={200}
          />
        </label>
        <label className="lab-field">
          研究目的
          <textarea
            className="lab-purpose"
            value={purpose}
            onChange={(event) => setPurpose(event.target.value)}
            maxLength={1000}
          />
        </label>
        <div className="lab-form-grid">
          <label className="lab-field">
            Received 数量
            <input
              type="number"
              min={0}
              max={10000}
              value={count}
              onChange={(event) => setCount(event.target.value)}
            />
          </label>
          <label className="lab-field">
            种子
            <input
              type="number"
              min={0}
              value={seed}
              onChange={(event) => setSeed(event.target.value)}
            />
          </label>
        </div>
        <div className="lab-form-grid">
          <label className="lab-field">
            链路模型
            <select
              value={topology}
              onChange={(event) =>
                setTopology(event.target.value as typeof topology)
              }
            >
              <option value="chain">连续链路</option>
              <option value="return">交替回返</option>
            </select>
          </label>
          <label className="lab-field">
            日期行为
            <select
              value={date}
              onChange={(event) => setDate(event.target.value as typeof date)}
            >
              <option value="valid">正常递增</option>
              <option value="backwards">时间倒序</option>
              <option value="invalid">无效日期</option>
              <option value="unknown_timezone">未知时区 -0000</option>
            </select>
          </label>
        </div>
        <div className="lab-form-grid">
          <label className="lab-field">
            Received 折行
            <select
              value={folding}
              onChange={(event) =>
                setFolding(event.target.value as typeof folding)
              }
            >
              <option value="none">不折行</option>
              <option value="space">SP 空格</option>
              <option value="tab">HTAB 制表符</option>
            </select>
          </label>
          <label className="lab-field">
            换行字节
            <select
              value={newline}
              onChange={(event) =>
                setNewline(event.target.value as typeof newline)
              }
            >
              <option value="crlf">CRLF</option>
              <option value="lf">LF</option>
            </select>
          </label>
        </div>
        <div className="lab-form-grid">
          <label className="lab-field">
            最长行目标 / bytes
            <input
              type="number"
              placeholder="留空：自然长度"
              value={line}
              onChange={(event) => setLine(event.target.value)}
            />
          </label>
          <label className="lab-field">
            头区目标 / bytes
            <input
              type="number"
              placeholder="留空：自然大小"
              value={headerSize}
              onChange={(event) => setHeaderSize(event.target.value)}
            />
          </label>
        </div>
        <p className="lab-form-note">
          目标包含字段字节，行长不含换行符。不能实现的尺寸组合会明确拒绝。
        </p>
        <details className="lab-advanced">
          <summary>字段歧义与可复现参数</summary>
          <label className="lab-field">
            固定基准时间
            <input
              value={time}
              onChange={(event) => setTime(event.target.value)}
            />
          </label>
          <label className="lab-field">
            Received 位置
            <select
              value={position}
              onChange={(event) =>
                setPosition(event.target.value as typeof position)
              }
            >
              <option value="first">有序字段之前</option>
              <option value="last">有序字段之后</option>
            </select>
          </label>
          <label className="lab-check">
            <input
              type="checkbox"
              checked={colon}
              onChange={(event) => setColon(event.target.checked)}
            />
            冒号前加入空格
          </label>
          <label className="lab-field">
            有序字段 JSON
            <textarea
              className="lab-header-json"
              value={headers}
              onChange={(event) => setHeaders(event.target.value)}
              spellCheck={false}
            />
          </label>
          <div className="lab-small-actions">
            <button type="button" onClick={() => duplicate("From")}>
              + 重复 From
            </button>
            <button type="button" onClick={() => duplicate("Message-ID")}>
              + 重复 Message-ID
            </button>
          </div>
          <p className="lab-form-note">
            列表顺序就是输出顺序；可移动或重复任意字段实例。
          </p>
        </details>
        <div className="lab-sweep">
          <label className="lab-check">
            <input
              type="checkbox"
              checked={batch}
              onChange={(event) => setBatch(event.target.checked)}
            />
            单变量批量生成
          </label>
          {batch && (
            <>
              <label className="lab-field">
                唯一变化轴
                <select
                  value={axis}
                  onChange={(event) =>
                    setAxis(event.target.value as SweepSpec["axis"])
                  }
                >
                  <option value="received_count">Received 数量</option>
                  <option value="max_line_bytes">最长物理行</option>
                  <option value="header_bytes">头区字节数</option>
                </select>
              </label>
              <label className="lab-field">
                扫描值
                <input
                  value={values}
                  onChange={(event) => setValues(event.target.value)}
                />
              </label>
              <p className="lab-form-note">
                保持其余参数固定。最多 20 份；样本组不代表连续传输跳数。
              </p>
            </>
          )}
        </div>
        <button type="button" className="analyze-button" onClick={submit}>
          {busy ? (
            <>
              <span className="spinner" />
              正在生成与归档
            </>
          ) : (
            "生成并保存实验 →"
          )}
        </button>
      </fieldset>
    </div>
  );
}
