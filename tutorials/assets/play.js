/* Playable explanations for the eight MailSecLab paper pages.
   Addresses drawn here are teaching stand-ins. Measured numbers are the papers'. */

(function () {
  const $ = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  const button = (label, pressed, onClick) => {
    const b = $("button", null, label);
    b.type = "button";
    if (pressed != null) b.setAttribute("aria-pressed", pressed ? "true" : "false");
    b.addEventListener("click", onClick);
    return b;
  };

  const setFb = (node, kind, text) => {
    node.className = "lab-fb " + (kind || "");
    node.textContent = text;
  };

  const mountOf = (root) => root.querySelector(".lab-mount");

  function sanchez(root) {
    const host = mountOf(root);
    const years = {
      2007: { n: "316,746", len: 2.57, short: 45, nlc: 91 },
      2008: { n: "722,579", len: 2.34, short: 68, nlc: 97.1 },
      2009: { n: "802,986", len: 2.34, short: 66, nlc: 96.7 },
    };
    let forged = false;
    let step = 0;
    let year = 2008;

    const steps = () => [
      "先看整条链。RFC 5321 要求最新的 Received 写在最上面。收件人写的 To 可以伪造，所以收件域改从 Delivered-To 取：这里是 untroubled.org。",
      "untroubled.org 的 MX 不是它自己，而是 mx.futurequest.net。若只拿「from 域名 ≠ 收件域」当边界，会把这家代收服务器认错。论文用 MX 集合避免这一点。",
      "从最下面的 Received 往上找，第一条 by-domain 落在 MX 集合里的，是 FIMTA（收件侧第一台内部 MTA）。教学链里是 mail.untroubled.org 这一跳。",
      "再往外，第一个不属于 MX 集合的 from-address，才是 FEMTA。只有这一跳的 from 是由收件侧写下的，可以当作归因点。它上面的跳，发件人都能预置。",
      forged
        ? "伪造前缀用了另一段 /16（198.51.100.0/16，对 203.0.113.0/16）。相邻跳不再网络级一致（NLC），断开点就是插入处。FEMTA 的 from-address 不变。"
        : "2007–2009 的垃圾邮件大多很短：大量路径在 FIMTA 之前只有一跳。打开「伪造前缀」可以看到 NLC 在 /16 不一致处断开，而 FEMTA 仍然是那一个地址。",
    ];

    const draw = () => {
      host.replaceChildren();
      const grid = $("div", "lab-grid");
      const stage = $("div", "stage");
      stage.append($("p", "tiny", "上 = 最新。地址是 RFC 5737 教学示例，不是档案里的真实主机。"));

      const hops = [
        { role: forged ? "伪造" : "外部", cls: forged ? "bad" : "", txt: forged ? "from 198.51.100.8 by 203.0.113.44" : "（这一跳可以不存在）", on: step === 4 && forged },
        { role: "FEMTA", cls: step >= 3 ? "good" : "", txt: "from 203.0.113.44 by mx.futurequest.net", on: step === 3 || (step === 4 && !forged) },
        { role: "FIMTA", cls: step === 2 ? "on" : step > 2 ? "good" : "", txt: "from mx.futurequest.net by mail.untroubled.org", on: step === 2 },
        { role: "投递", cls: step === 0 ? "on" : "", txt: "Delivered-To: bait@untroubled.org", on: step === 0 },
      ];
      if (!forged) hops.shift();
      hops.forEach((h) => {
        const row = $("div", "hop" + (h.on ? " on" : "") + (h.cls && !h.on ? " " + h.cls : ""));
        row.append($("div", "role", h.role), $("div", "txt", h.txt));
        stage.append(row);
      });
      if (step === 1) {
        stage.append($("p", "tiny", "MX(untroubled.org) = { mx.futurequest.net }。第三方案例来自论文对 bait 域的说明。"));
      }

      const side = $("div", "side");
      const fb = $("p", "lab-fb");
      setFb(fb, step >= 3 ? "ok" : "info", steps()[step]);
      const ybox = $("div", "stage");
      ybox.append($("p", "tiny", year + " 年，" + years[year].n + " 封。柱长按论文表格。"));
      const y = years[year];
      [
        ["平均路径", (y.len / 4) * 100, y.len.toFixed(2), ""],
        ["长度 ≤ 2", y.short, y.short + "%", "ok"],
        ["NLC ≤ 2", y.nlc, y.nlc + "%", "alt"],
      ].forEach(([name, width, label, kind]) => {
        const row = $("div", "bar-row");
        row.append($("span", null, name));
        const track = $("div", "track");
        const fill = $("span", kind);
        track.append(fill);
        row.append(track, $("span", null, label));
        ybox.append(row);
        requestAnimationFrame(() => { fill.style.width = Math.min(100, width) + "%"; });
      });
      side.append(fb, ybox);
      grid.append(stage, side);
      host.append(grid);

      const controls = $("div", "lab-controls");
      controls.append(
        button("上一步", null, () => { step = Math.max(0, step - 1); draw(); }),
        button("下一步", null, () => { step = Math.min(4, step + 1); draw(); }),
        button(forged ? "去掉伪造前缀" : "加上伪造前缀", forged, () => { forged = !forged; step = 4; draw(); })
      );
      [2007, 2008, 2009].forEach((y) => {
        controls.append(button(String(y), year === y, () => { year = y; draw(); }));
      });
      host.append(controls);
    };
    draw();
  }

  function vanstaden(root) {
    const host = mountOf(root);
    const full = [
      { from: "alice-mta.test", by: "relay.example" },
      { from: "relay.example", by: "mx.lab.test" },
      { from: "mx.lab.test", by: "mail.lab.test" },
    ];
    let dropped = false;
    let cursor = 0;

    const analyze = (hops) => {
      const trace = [{
        focus: 0,
        ok: null,
        text: "Step 1–2：队列从最后一条 Received 排到第一条。标准头区里最后一条是更早的那一跳。先记住它的 by：" + hops[0].by + "。",
      }];
      let remembered = hops[0].by;
      const proven = [];
      const gap = [];
      let gapFound = false;
      for (let i = 1; i < hops.length; i++) {
        const same = hops[i].from === remembered;
        if (same) proven.push(hops[i].by);
        else {
          proven.push(hops[i].by);
          gap.push(hops[i].from);
          gapFound = true;
        }
        trace.push({
          focus: i,
          ok: same,
          left: hops[i].from,
          right: remembered,
          text: same
            ? "Step 3–4：下一跳的 from 等于记下的 by。把本跳的 by「" + hops[i].by + "」放进 proven。"
            : "Step 3 与 5：from「" + hops[i].from + "」对不上记下的「" + remembered + "」。sending 进 gap，receiving「" + hops[i].by + "」仍进 proven，并置 gap-found。",
        });
        remembered = hops[i].by;
      }
      trace.push({
        focus: -1,
        ok: !gapFound,
        text: gapFound
          ? "Step 7：gap detected。proven 是写下增强 Received 的主机；gap 是对不上的 sending，论文把它当作最后已知、但没按增强规则补跳的主机。"
          : "Step 7：no gap found。论文第 V 节写明：头仍是明文，对手还能改。只有整条链没有缺口时，才用这些 send-receive 对追来源。无缺口 ≠ 不可伪造。",
      });
      return { trace, proven, gap };
    };

    const draw = () => {
      const hops = dropped ? [full[0], full[2]] : full.slice();
      const { trace, proven, gap } = analyze(hops);
      cursor = Math.max(0, Math.min(cursor, trace.length - 1));
      const frame = trace[cursor];
      host.replaceChildren();
      const grid = $("div", "lab-grid");
      const stage = $("div", "stage");
      stage.append($("p", "tiny", "从上到下 = 从更早到更新。哈希串是示意，不是对这两个名字算出的 SHA-1。"));
      hops.forEach((h, i) => {
        const row = $("div", "hop" + (frame.focus === i ? " on" : ""));
        row.append(
          $("div", "role", "跳 " + (i + 1)),
          $("div", "txt", "from " + h.from + " ; h·" + h.from.slice(0, 4) + "\nby " + h.by + " ; h·" + h.by.slice(0, 4))
        );
        stage.append(row);
      });
      if (dropped) stage.append($("p", "tiny", "中间那一跳被拿掉了：relay.example → mx.lab.test 的一对不见了。"));

      const side = $("div", "side");
      if (frame.left) {
        const eq = $("div", "eq");
        eq.append($("span", null, "from " + frame.left), $("b", "mark " + (frame.ok ? "yes" : "no"), frame.ok ? "=" : "≠"), $("span", null, "by " + frame.right));
        side.append(eq);
      }
      const lists = $("div", "lists");
      const pbox = $("div", "listbox ok");
      pbox.append($("strong", null, "proven"));
      pbox.append(document.createTextNode(proven.length ? proven.join(" · ") : "还没有"));
      const gbox = $("div", "listbox bad");
      gbox.append($("strong", null, "gap"));
      gbox.append(document.createTextNode(gap.length ? gap.join(" · ") : "空"));
      lists.append(pbox, gbox);
      const fb = $("p", "lab-fb");
      setFb(fb, frame.ok === false ? "warn" : frame.ok ? "ok" : "info", frame.text);
      side.append(lists, fb);
      grid.append(stage, side);
      host.append(grid);

      const controls = $("div", "lab-controls");
      controls.append(
        button("上一步", null, () => { cursor -= 1; draw(); }),
        button("下一步", null, () => { cursor += 1; draw(); }),
        button(dropped ? "补回中间跳" : "去掉中间跳", dropped, () => { dropped = !dropped; cursor = dropped ? 1 : 0; draw(); })
      );
      host.append(controls);
    };
    draw();
  }

  function chen(root) {
    const host = mountOf(root);
    const modes = {
      A6: {
        title: "A6 · 两个 From",
        server: "DMARC 用第一条：alice@legitimate.com，判定 pass。",
        client: "iCloud Web 显示最后一条：admin@paypal.com。",
        note: "论文：19/29 个实现接受多个 From。iCloud Web 和 Windows Mail 显示最后一条；macOS Mail 两条都显示；其余大多显示第一条。服务器用第一条做 DMARC。这里演示的是 iCloud Web 那种错位，不是所有客户端。",
      },
      A10: {
        title: "A10 · 编码后的显示名",
        server: "服务器不解码，DMARC 用尖括号里的 attack.com。",
        client: "网页和多数 MUA 会解码，屏幕上是 admin@legitimate.com。",
        note: "论文点名 Yahoo、Outlook、iCloud、Fastmail、Zoho、Tutanota 的服务器不解码，但它们的网页界面和多数 MUA 会解码。认证对象和用户看见的对象不是同一个。",
      },
      A3: {
        title: "A3 · DKIM 选择器里的 NUL",
        server: "签名上的 d= 仍写成 legitimate.com，验证看起来通过。",
        client: "用户只看见验证通过，不知道公钥查询在 NUL 处被截成了攻击者的域。",
        note: "论文：选择器里的 \\x00 让 C 字符串语义的解析器截断 DNS 查询，公钥落到攻击者控制的名字下。Gmail 在 2020 年修复。这是组件之间对同一字节的解释不同，不是用户点错了。",
      },
    };
    let mode = "A6";

    const draw = () => {
      const m = modes[mode];
      host.replaceChildren();
      const stage = $("div", "stage");
      stage.append($("p", "tiny", m.title + "。左边是收信服务器用来认证的解释，右边是用户看见的解释。"));
      const split = $("div", "split");
      const server = $("div", "pane server");
      server.append($("header", null, "收信服务器"));
      const sb = $("div", "body");
      sb.append($("div", "who", mode === "A3" ? "DNS 查询被截断" : "认证用的身份"));
      sb.append($("p", null, m.server));
      server.append(sb);
      const client = $("div", "pane client");
      client.append($("header", null, "用户界面"));
      const cb = $("div", "body");
      cb.append($("div", "who", mode === "A3" ? "只看到 pass" : "屏幕上的发件人"));
      cb.append($("p", null, m.client));
      client.append(cb);
      split.append(server, client);
      stage.append(split);
      if (mode === "A3") {
        const bytes = $("div", "bytes");
        bytes.append(document.createTextNode("selector\\x00.attack.com._domainkey → 查询停在 "));
        bytes.append($("span", "hit", "selector._domainkey.attack.com"));
        stage.append(bytes);
      }
      host.append(stage);
      const fb = $("p", "lab-fb warn");
      setFb(fb, "warn", m.note);
      host.append(fb);
      const controls = $("div", "lab-controls");
      Object.keys(modes).forEach((id) => {
        controls.append(button(modes[id].title, mode === id, () => { mode = id; draw(); }));
      });
      host.append(controls);
    };
    draw();
  }

  function shen(root) {
    const host = mountOf(root);
    const stages = [
      { id: "send", name: "发送", attacks: "A1 登录名 ≠ MAIL FROM；A2 MAIL FROM ≠ From。14/30 个服务不限制 A2。" },
      { id: "recv", name: "接收验证", attacks: "A3 空 MAIL FROM 被当成 SPF none（13 个服务）；A4 多个 From（19 个服务接受）；A7 MIME 编码地址；A8 子域。" },
      { id: "fwd", name: "转发", attacks: "A9 开放转发（12 个服务）；A10 转发器用自己的域重签 DKIM；A11 Office 365 与 Zoho 的 ARC 错误。" },
      { id: "ui", name: "界面", attacks: "A12 同形域名；A13 不可见字符截断；A14 从右到左覆盖。只有 12/30 个服务在界面做发件人不一致检查。" },
    ];
    let picked = 3;
    let cocktail = false;

    const draw = () => {
      host.replaceChildren();
      const stage = $("div", "stage");
      const chain = $("div", "chain");
      stages.forEach((s, i) => {
        if (i) {
          const broken = cocktail ? i === 3 : i === picked;
          chain.append($("span", "joint" + (broken ? " broken" : "")));
        }
        chain.append(button(s.name, !cocktail && picked === i, () => { cocktail = false; picked = i; draw(); }));
      });
      stage.append(chain);
      stage.append($("p", "tiny", cocktail
        ? "预设复现论文案例 1，不是让你去发这封信。Yahoo 侧认证对准第一条 From，iCloud 把第二条画给用户。"
        : "点某一环，只看这一环自己的攻击。最弱的一环决定整封信看起来像不像真的。"));
      host.append(stage);
      const fb = $("p", "lab-fb");
      if (cocktail) {
        setFb(fb, "warn", "案例 1：攻击者用自己的 Yahoo 账号发出。第一条 From 是 oscar@yahoo.com，通过 Yahoo 的同域检查；第二条 From 是 admin@paypal.com。iCloud 不拒绝多个 From，用第一条做 DMARC（yahoo.com，pass），界面显示第二条。SPF、DKIM、DMARC 都对 yahoo 对齐通过，界面却写成 paypal，而且没有不一致提示。");
      } else {
        setFb(fb, "info", stages[picked].attacks + " 测量范围是 30 个服务和 23 个客户端；论文说每个受测系统至少中一种。");
      }
      host.append(fb);
      const controls = $("div", "lab-controls");
      controls.append(button("载入案例：Yahoo 发出，iCloud 显示", cocktail, () => { cocktail = true; draw(); }));
      host.append(controls);
    };
    draw();
  }

  function liu(root) {
    const host = mountOf(root);
    const modes = {
      PMF: {
        mail: "alice@univ.edu", from: "alice@univ.edu", rcpt: "alice@gmail.com",
        spf: "fail", dmarc: "未对齐则失败",
        shift: [],
        text: "PMF 只改 RCPT TO。MAIL FROM 仍是原发件人，但连接 IP 已经是转发器，原域的 SPF 通常不包括这个 IP，所以 SPF 失败。Fastmail、iCloud、Yahoo 等 7 家是这种。",
      },
      MFEF: {
        mail: "alice@univ.edu", from: "alice@univ.edu", rcpt: "alice@gmail.com",
        spf: "fail", dmarc: "仍看 SPF",
        shift: ["mail"],
        text: "MFEF 把 MAIL FROM 设成和 From 一样，例子是 Outlook / Hotmail / O365 和 Freemail。IP 仍是转发器，SPF 通常还是失败。",
      },
      REM: {
        mail: "alice-xyz@univ.edu", from: "alice@univ.edu", rcpt: "user@univ.edu",
        spf: "pass", dmarc: "fail",
        shift: ["mail"],
        text: "REM 把 MAIL FROM 改到转发器自己的域，SPF 可以通过。From 没改，和 MAIL FROM 对不齐，DMARC 对齐失败。Gmail、Zoho 和多数列表是这种。",
      },
      MOD: {
        mail: "list@univ.edu", from: "list@univ.edu", rcpt: "user@univ.edu",
        spf: "pass", dmarc: "pass",
        shift: ["mail", "from"],
        text: "REM+MOD 连 From 也改成列表地址。SPF 和 DMARC 都能过，但用户看见的发件人变成了转发器。论文里只有 Gaggle 这样做。",
      },
      SHARE: {
        mail: "（Outlook 代发）", from: "bush@state.gov", rcpt: "任意收件人",
        spf: "pass", dmarc: "可被带过",
        shift: ["from"],
        text: "这不是上面四种改写。§5.1：state.gov 的 SPF 收录了 Outlook 的地址。从 Outlook 发出、From 写成 bush@state.gov 时，SPF 能过。论文估计约 12% 的 Alexa Top-100K、约 8% 的 Top-1M 有这个暴露，转发侧包括 Outlook、iCloud、Freemail、Hushmail、Mail2World、Runbox。",
      },
    };
    let mode = "PMF";

    const draw = () => {
      const m = modes[mode];
      host.replaceChildren();
      const stage = $("div", "stage");
      const row = $("div", "field-row");
      [
        ["mail", "MAIL FROM", m.mail],
        ["from", "From", m.from],
        ["rcpt", "RCPT TO", m.rcpt],
      ].forEach(([id, name, value]) => {
        const shifted = m.shift.includes(id);
        const box = $("div", "field" + (shifted ? " shift" : ""));
        box.append($("b", null, name), document.createTextNode(value));
        row.append(box);
      });
      stage.append(row);
      const stamps = $("div", "stamp-row");
      stamps.append(
        $("span", "stamp " + (m.spf === "pass" ? "pass" : "fail"), "SPF " + m.spf),
        $("span", "stamp " + (m.dmarc === "fail" ? "fail" : "pass"), "DMARC " + m.dmarc)
      );
      stage.append(stamps);
      host.append(stage);
      const fb = $("p", "lab-fb");
      setFb(fb, m.spf === "fail" || m.dmarc === "fail" ? "warn" : "ok", m.text);
      host.append(fb);
      const controls = $("div", "lab-controls");
      [
        ["PMF", "PMF"],
        ["MFEF", "MFEF"],
        ["REM", "REM"],
        ["MOD", "REM+MOD"],
        ["SHARE", "§5.1 共享 SPF"],
      ].forEach(([id, label]) => {
        controls.append(button(label, mode === id, () => { mode = id; draw(); }));
      });
      host.append(controls);
    };
    draw();
  }

  function luo(root) {
    const host = mountOf(root);
    const checks = [
      { pct: 66, text: "66%：MX 认定的发送 IP 和声称的源 IP 在同一个 AS。AS 级统计对路径里的小改动比较稳。" },
      { pct: 82.2, text: "再加上 16.2 个百分点：同一对 IP 在同期正常邮件里出现过。累计 82.2%。" },
      { pct: 84.2, text: "再加上 2 个百分点：整条中继 IP 与正常邮件完全一致，更像账号被盗，而不是临时拼出来的路径。累计 84.2%。" },
      { pct: 90.6, text: "再加上 6.4 个百分点：收件 MX 在 Received 里只出现一次，且等于源 IP 或与之同 AS。合计至少 90.6% 没有会扭曲 AS 级分析的源 IP 篡改证据。剩下的 9.4% 路径长度分布和正常邮件一样。" },
    ];
    let step = 0;
    let walk = 0;

    const draw = () => {
      host.replaceChildren();
      const grid = $("div", "lab-grid");
      const stage = $("div", "stage");
      stage.append($("p", "tiny", "从靠近收件人的一跳往外走。教学链，不是某封真实钓鱼邮件。"));
      const hops = [
        { role: "更早", txt: "from 203.0.113.20 by 203.0.113.44", on: walk >= 2 },
        { role: "FEMTA", txt: "from 203.0.113.44 by mx.customer.protection.outlook.com", on: walk === 1 },
        { role: "FIMTA", txt: "by-domain 对上收件 MX", on: walk === 0 },
      ];
      hops.forEach((h) => {
        const row = $("div", "hop" + (h.on ? " on" : " dim"));
        row.append($("div", "role", h.role), $("div", "txt", h.txt));
        stage.append(row);
      });

      const side = $("div", "stage");
      side.append($("p", "tiny", "四项检验是累加的，不是四选一。"));
      const row = $("div", "bar-row");
      row.append($("span", null, "可解释比例"));
      const track = $("div", "track");
      const fill = $("span", "ok");
      track.append(fill);
      row.append(track, $("span", null, checks[step].pct + "%"));
      side.append(row);
      requestAnimationFrame(() => { fill.style.width = checks[step].pct + "%"; });
      const contrast = $("div", "bar-row");
      contrast.append($("span", null, "前 200 个 IP"));
      const t2 = $("div", "track");
      const a = $("span", "alt");
      t2.append(a);
      contrast.append(t2, $("span", null, "钓鱼 ≈50%"));
      side.append(contrast);
      requestAnimationFrame(() => { a.style.width = "50%"; });
      side.append($("p", "tiny", "同样这 200 个 IP 在正常邮件里不到 1%。前 100 个 AS 约承载 80% 的钓鱼和 70% 的正常邮件；去掉 Amazon 与 Microsoft 之后，正常邮件占比会掉到 10% 以下。"));
      grid.append(stage, side);
      host.append(grid);
      const fb = $("p", "lab-fb");
      const walkText = [
        "先找 FIMTA：从下往上，第一条 by-domain 对上收件人 MX 的跳。",
        "FIMTA 的上一跳是 FEMTA。它的 IP 和域名是收件侧盖上去的，用来做来源，而不是用发件人自己写的最外层 Received。",
        "私网和保留地址先丢掉，再取第一个公网 IP，并用 Team Cymru 映到 ASN。来源定位之后，才用右边的四项检验问：这批 IP 像不像被篡改过。",
      ][walk];
      setFb(fb, "info", walkText + " " + checks[step].text);
      host.append(fb);
      const controls = $("div", "lab-controls");
      controls.append(
        button("沿链再走一跳", null, () => { walk = Math.min(2, walk + 1); draw(); }),
        button("加上一项保真检验", null, () => { step = Math.min(3, step + 1); draw(); }),
        button("重置", null, () => { walk = 0; step = 0; draw(); })
      );
      host.append(controls);
    };
    draw();
  }

  function wang(root) {
    const host = mountOf(root);
    const state = { pass: true, accept: true, pipe: true, nul: false };

    const draw = () => {
      const split = state.pass && state.accept && state.pipe;
      host.replaceChildren();
      const stage = $("div", "stage");
      const bytes = $("div", "bytes");
      bytes.append(document.createTextNode("DATA\\r\\n 正文 … "));
      bytes.append($("span", split ? "hit" : "", state.nul ? "\\r\\n\\x00.\\r\\n" : "\\n.\\n"));
      bytes.append(document.createTextNode(" MAIL FROM:<phish> … \\r\\n.\\r\\n"));
      stage.append(bytes);
      const letters = $("div", "letters");
      const left = $("div", "letter show" + (split ? " left" : ""));
      left.append($("strong", null, "第一封"), $("p", null, "发送端以为 DATA 要到 \\r\\n.\\r\\n 才结束。"));
      const right = $("div", "letter" + (split ? " show right" : ""));
      right.append($("strong", null, split ? "第二封被拆出来" : "还是正文"));
      right.append($("p", null, split
        ? "接收端把非标准结束符当成 DATA 结束，流水线又把后面的字节当成新事务。"
        : "三个条件缺一个，后面的字节就不会变成第二封信。"));
      letters.append(left, right);
      stage.append(letters);
      host.append(stage);

      const fb = $("p", "lab-fb");
      const payload = state.nul
        ? "当前载荷是 A7：\\r\\n\\x00.\\r\\n，论文用它打 C 字符串在 NUL 处截断。"
        : "当前载荷是 A1：\\n.\\n，这是 SEC Consult 已经公开的一种结束符。";
      const missing = [];
      if (!state.pass) missing.push("发送端会滤掉这种结束符");
      if (!state.accept) missing.push("接收端只认 CRLF.CRLF");
      if (!state.pipe) missing.push("没有命令流水线，剩余字节仍停在正文里");
      if (missing.length) {
        setFb(fb, "ok", "拆不成第二封，因为" + missing.join("；") + "。" + payload + " 论文另有测量：发送侧 18/20 会原样送出（Gmail、Yahoo、Zoho、AOL 对带 NUL 的 A8–A13 都会放行）；接收侧 8/22 至少接受一种载荷，Gmail、Yahoo、Outlook、iCloud 的接收侧未受影响。");
      } else {
        setFb(fb, "warn", "三个条件同时成立，一封信被拆成两封。" + payload + " 公开服务综合暴露面是 19/22；自建服务 6,917 个里 1,577 个暴露。这两个数是论文的测量，不是这个动画算出来的。Sina 会显示走私进去的那封并丢掉第一封。");
      }
      host.append(fb);

      const controls = $("div", "lab-controls");
      [
        ["pass", "1. 发送端放行非标准结束符"],
        ["accept", "2. 接收端把它当 DATA 结束"],
        ["pipe", "3. 打开命令流水线"],
      ].forEach(([key, label]) => {
        controls.append(button(label, state[key], () => { state[key] = !state[key]; draw(); }));
      });
      controls.append(button(state.nul ? "载荷 A7（NUL）" : "载荷 A1（裸 LF）", state.nul, () => { state.nul = !state.nul; draw(); }));
      host.append(controls);
    };
    draw();
  }

  function mime(root) {
    const host = mountOf(root);
    const modes = {
      D3: {
        input: "Content-Transfer-Encoding: base64\nContent-Transfer-Encoding: 7bit\n\nR1RVQkU=",
        filter: "SpamAssassin 采用第二条，按 7bit 原文看，不把正文解码，GTUBE 测试串仍是编码。",
        client: "Evolution / Thunderbird 采用第一条，按 base64 解码，正文里出现 GTUBE。",
        note: "D3 能绕过 SpamAssassin，到达 Evolution 和 Thunderbird。ClamAV 在这组实验里没有被这 15 类差异走私过去；它经常「不管怎样都解码」，反而是四个目标里最防守的一个。",
      },
      D4: {
        input: "Content-Type: text/plain\nContent-Type: multipart/alternative\n\npreamble: GTUBE\n--bound",
        filter: "SpamAssassin 采用第一个 Content-Type，把信当成 text/plain，看不到 multipart 导言里的 GTUBE。",
        client: "客户端采用第二个 Content-Type，按 multipart 渲染导言，GTUBE 出现在用户侧。",
        note: "D4 同样绕过 SpamAssassin，对 Evolution 和 Thunderbird 可见。两个 Content-Type 谁生效，论文记的是：Evolution 用第一条，ClamAV 和 SpamAssassin 用第二条。",
      },
      D11: {
        input: "Content-Transfer-Encoding:: base64\n\nR1RVQkU=",
        filter: "多了一个冒号。SpamAssassin 整条拒绝这个头，于是不解码正文。",
        client: "Evolution 仍然按 base64 解码并显示 GTUBE。Thunderbird 也拒绝这个头，所以这一条只对 Evolution 成立。",
        note: "D11 的影响面比 D3/D4 窄：论文写的是只绕过到 Evolution。AFL++ 得到 448 个差异样本，T-Reqs 最小化后 349 个；人工归并成 D1–D15 这 15 个根因，其中可利用的是 D3、D4、D11。",
      },
    };
    let mode = "D3";

    const draw = () => {
      const m = modes[mode];
      host.replaceChildren();
      const stage = $("div", "stage");
      const bytes = $("pre", "bytes");
      bytes.textContent = m.input;
      stage.append($("p", "tiny", "同一段输入。R1RVQkU= 是单词 GTUBE 的 base64，用来表示「解码前 / 解码后」，不是论文附件里的原始样本。"));
      stage.append(bytes);
      const split = $("div", "split");
      const filter = $("div", "pane server");
      filter.append($("header", null, "SpamAssassin 看见"));
      filter.append($("div", "body", m.filter));
      const client = $("div", "pane client");
      client.append($("header", null, "客户端看见"));
      const body = $("div", "body");
      body.append($("p", null, m.client));
      body.append($("p", "who", "GTUBE"));
      client.append(body);
      split.append(filter, client);
      stage.append(split);
      host.append(stage);
      const fb = $("p", "lab-fb warn");
      setFb(fb, "warn", m.note);
      host.append(fb);
      const controls = $("div", "lab-controls");
      Object.keys(modes).forEach((id) => {
        controls.append(button(id, mode === id, () => { mode = id; draw(); }));
      });
      host.append(controls);
    };
    draw();
  }

  const labs = { sanchez, vanstaden, chen, shen, liu, luo, wang, mime };

  document.querySelectorAll("[data-lab]").forEach((root) => {
    const fn = labs[root.getAttribute("data-lab")];
    if (fn) fn(root);
  });
})();
