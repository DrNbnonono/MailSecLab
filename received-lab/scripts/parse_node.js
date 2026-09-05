#!/usr/bin/env node
// Phase 3C parser: Node.js mailparser (simpleParser). Reports the structure
// as *this parser* sees the byte stream.
const fs = require('fs');
const { simpleParser } = require('mailparser');

(async () => {
  const out = { parser: 'node-mailparser', version: require('mailparser/package.json').version };
  try {
    const p = await simpleParser(fs.readFileSync(process.argv[2]));
    out.parse_error = null;
    out.defects = (p.defects || []).map(d => (d && d.type) ? d.type : String(d));
    out.header_entries = p.headerLines ? p.headerLines.length : (p.headers ? p.headers.size : 0);
    let received = 0;
    if (p.headers) {
      for (const [k, v] of p.headers) {
        if (String(k).toLowerCase() === 'received') received += Array.isArray(v) ? v.length : 1;
      }
    }
    out.received_count = received;
    out.from_present = !!(p.from && ((p.from.text && p.from.text.length) || (p.from.value && p.from.value.length)));
    out.subject_present = p.subject != null && p.subject !== '';
    out.message_id_present = !!p.messageId;
    const text = p.text || '';
    out.from_in_body = text.includes('From: Alice');
    out.subject_in_body = text.includes('Subject: [');
  } catch (e) {
    out.parse_error = String((e && e.message) || e);
    out.defects = [];
    out.header_entries = 0; out.received_count = 0;
    out.from_present = false; out.subject_present = false; out.message_id_present = false;
    out.from_in_body = false; out.subject_in_body = false;
  }
  console.log(JSON.stringify(out));
})();
