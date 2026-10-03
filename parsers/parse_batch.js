// 批量 parse 探针（Node mailparser）：目录 -> 每文件一行 JSON。
// 与 parse.js 同口径，仅加 case 定位键与 field_count 维度，供 gramfuzz
// stage-1 批量差分。比较元组 (received_count, from_in_headers, field_count)，
// field_count 为 headers Map 键数（mailparser 键小写、同键合并 = 去重字段名数）。
// 运行需 NODE_PATH=/app/node_modules（w3 记录，parser-node 容器）。
const fs = require("fs");
const path = require("path");
const simpleParser = require("mailparser").simpleParser;

(async () => {
  const dir = process.argv[2];
  const files = fs.readdirSync(dir).filter((x) => x.endsWith(".eml")).sort();
  for (const f of files) {
    const out = { case: path.basename(f, ".eml") };
    try {
      const msg = await simpleParser(fs.readFileSync(path.join(dir, f)));
      const rec = msg.headers.get("received");
      let n = 0;
      for (const _ of msg.headers) n++;
      out.received_count = rec == null ? 0 : Array.isArray(rec) ? rec.length : 1;
      out.from_in_headers = msg.headers.has("from");
      out.field_count = n;
    } catch (e) {
      out.error = String(e);
    }
    console.log(JSON.stringify(out));
  }
})();
