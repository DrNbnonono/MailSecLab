const simpleParser = require("mailparser").simpleParser;
(async () => {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  let out;
  try {
    const msg = await simpleParser(Buffer.concat(chunks));
    const rec = msg.headers.get("received");
    out = {
      received_count: rec == null ? 0 : Array.isArray(rec) ? rec.length : 1,
      from_in_headers: msg.headers.has("from"),
    };
  } catch (e) {
    out = { error: String(e) };
  }
  console.log(JSON.stringify(out));
})();
