// MailSecLab — Tutorial Static Server
// Pure Node.js (http + fs + path), no external dependencies.
// Serves the tutorials/ folder: index listing + per-paper pages.
//
// Usage:
//   node server.js               # default port 5180
//   PORT=8080 node server.js     # custom port

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const TUTORIALS_DIR = path.join(ROOT, 'tutorials');
const PORT = parseInt(process.env.PORT || '5180', 10);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf',
  '.md': 'text/markdown; charset=utf-8',
};

// Embedded paper catalogue — keep in sync with tutorials/
const PAPERS = [
  {
    slug: '2010_sanchez_sdp',
    title: 'Understanding Forgery Properties of Spam Delivery Paths',
    authors: 'Sanchez, Duan, Dong',
    venue: 'CEAS 2010',
    year: 2010,
    tags: ['Received', 'Forgery', 'Trace'],
    src: '2010_ceas_sdp.pdf',
  },
  {
    slug: '2010_van_staden_forensic',
    title: 'Adding Digital Forensic Readiness to the Email Trace Header',
    authors: 'Van Staden, Venter',
    venue: 'ISSA 2010',
    year: 2010,
    tags: ['Forensics', 'Trace'],
    src: 'IEEE-2010-Adding digital forensic readiness.pdf',
  },
  {
    slug: '2020_chen_composition_kills',
    title: 'Composition Kills: A Case Study of Email Sender Authentication',
    authors: 'Chen, Paxson, Jiang',
    venue: 'USENIX Security 2020',
    year: 2020,
    tags: ['Authentication', 'Composition'],
    src: '2020_Chen_Composition_Kills_Email_Sender_Authentication.pdf',
  },
  {
    slug: '2021_shen_weak_links',
    title: 'Weak Links in Authentication Chains',
    authors: 'Shen et al.',
    venue: 'USENIX Security 2021',
    year: 2021,
    tags: ['SPF', 'DKIM', 'DMARC', 'ARC'],
    src: '2021_Shen_Weak_Links_in_Authentication_Chains.pdf',
  },
  {
    slug: '2023_liu_forward_pass',
    title: 'Forward Pass: Email Forwarding Mechanism and Policy Security',
    authors: 'Liu et al.',
    venue: 'IEEE EuroS&P 2023',
    year: 2023,
    tags: ['Forwarding', 'ARC', 'SPF'],
    src: '2023_Liu_Forward_Pass_Email_Forwarding.pdf',
  },
  {
    slug: '2025_luo_phishing',
    title: 'Characterizing the Networks Sending Enterprise Phishing Emails',
    authors: 'Luo et al.',
    venue: 'PAM 2025',
    year: 2025,
    tags: ['Phishing', 'Received', 'Infrastructure'],
    src: '2025_Luo_Characterizing_Enterprise_Phishing_Networks.pdf',
  },
  {
    slug: '2025_wang_smtp_smuggling',
    title: 'Email Spoofing with SMTP Smuggling',
    authors: 'Wang et al.',
    venue: 'USENIX Security 2025',
    year: 2025,
    tags: ['SMTP', 'Smuggling', 'MTA'],
    src: '2025_Wang_Email_Spoofing_with_SMTP_Smuggling.pdf',
  },
  {
    slug: '2025_andarzian_mime_fuzz',
    title: 'Email Smuggling with Differential Fuzzing of MIME Parsers',
    authors: 'Andarzian, Meyers, Poll',
    venue: 'IEEE SPW 2025',
    year: 2025,
    tags: ['MIME', 'Fuzzing', 'Differential'],
    src: '2025_Andarzian_Email_Smuggling_Differential_Fuzzing.pdf',
  },
];

function buildListing(activeSlug = null) {
  const navItems = PAPERS.map(p =>
    `<a href="/${p.slug}/"${p.slug === activeSlug ? ' class="active"' : ''}>${p.year}</a>`
  ).join('');

  const cards = PAPERS.map(p => `
    <a class="card" href="/${p.slug}/">
      <div class="meta">${p.venue} · ${p.authors}</div>
      <h3>${p.title}</h3>
      <p>${p.tags.map(t => `<span class="tag">${t}</span>`).join('')}</p>
    </a>
  `).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MailSecLab — References Tutorials</title>
<link rel="stylesheet" href="/tutorials/assets/style.css">
</head>
<body>
<header class="site">
  <a href="/">MailSecLab</a>
  <nav>${navItems}</nav>
</header>
<main>
  <h1>References — Paper Tutorials</h1>
  <p>This page indexes structured summaries of the eight peer-reviewed papers in
  <code>references/</code> of the MailSecLab repository. The summaries are designed to be read
  before (or alongside) the originals to support the project’s experiments on
  <code>Received:</code> trace forgery, sender authentication composition, SMTP smuggling,
  and MIME differential fuzzing.</p>
  <p>Each card links to a per-paper tutorial that preserves the original problem, methodology,
  results, and limitations, and ties them to the corresponding MailSecLab series (H/I/K, etc.).
  See <a href="https://github.com/Drnbnonono/MailSecLab">README.md</a> for the canonical project layout.</p>
  <div class="card-grid">${cards}</div>
</main>
<footer class="site">Served by MailSecLab tutorial server (Node ${process.versions.node})</footer>
</body>
</html>`;
}

function buildPaperNav(activeSlug) {
  return PAPERS.map(p =>
    `<a href="/${p.slug}/"${p.slug === activeSlug ? ' class="active"' : ''}>${p.year}</a>`
  ).join('');
}

function buildPaperHeader(p) {
  return `
<header class="site">
  <a href="/">MailSecLab</a>
  <nav>${buildPaperNav(p.slug)}</nav>
</header>`;
}

function send(res, status, body, type = 'text/html; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  res.end(body);
}

function serveFromFs(absPath, res) {
  fs.readFile(absPath, (err, data) => {
    if (err) {
      send(res, 404, '<h1>404</h1><p>Not found.</p>');
      return;
    }
    const ext = path.extname(absPath).toLowerCase();
    send(res, 200, data, MIME[ext] || 'application/octet-stream');
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let pathname = decodeURIComponent(url.pathname).replace(/\/+$/, '') || '/';

  // Root → listing
  if (pathname === '/') {
    return send(res, 200, buildListing());
  }

  // /tutorials/... direct asset routes
  if (pathname.startsWith('/tutorials/')) {
    const rel = pathname.slice('/tutorials'.length);
    const abs = path.join(TUTORIALS_DIR, rel);
    if (!abs.startsWith(TUTORIALS_DIR)) {
      return send(res, 403, 'Forbidden');
    }
    return serveFromFs(abs, res);
  }

  // /<slug>/ → per-paper index.html
  const m = pathname.match(/^\/([^/]+)\/?$/);
  if (m) {
    const slug = m[1];
    if (PAPERS.some(p => p.slug === slug)) {
      const abs = path.join(TUTORIALS_DIR, slug, 'index.html');
      if (fs.existsSync(abs)) {
        return serveFromFs(abs, res);
      }
    }
  }

  send(res, 404, `
<!doctype html><html><head><meta charset="utf-8"><title>404</title>
<link rel="stylesheet" href="/tutorials/assets/style.css"></head>
<body><header class="site"><a href="/">MailSecLab</a></header>
<main><h1>404</h1><p>Page not found. <a href="/">Back to index</a>.</p></main></body></html>`);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`MailSecLab tutorials running at http://127.0.0.1:${PORT}/`);
  console.log(`  ${PAPERS.length} paper(s) indexed.`);
});
