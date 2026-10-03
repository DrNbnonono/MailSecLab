# Paper skeleton (not submitted)

## Question

After a message is received, repaired, authenticated, and parsed, is the identity covered by the signature the identity a later component uses?

## What this run supports

- With one `h=` listing, perl Mail::DKIM and go-msgauth 0.6.8 follow bottom-up selection for From, Subject, and Message-ID. Adding a field above the signed instance keeps their result at pass. Adding it below changes the result to fail.
- dkimpy 1.1.8 and rspamd 3.4 fail when a second From is added in either position. For Subject and Message-ID, dkimpy still follows bottom-up selection, while rspamd fails for an added instance in either position.
- Repeating the field name in `h=` and omitting the null slot at signing time makes all four verifiers fail when an instance is added above or below. dkimpy 1.1.8 `select_headers()` does not hash a missing name, and a signature that includes the RFC null field is rejected by all four.
- The same From-above mutant is still accepted by perl and go-msgauth after three Postfix hops and is delivered. dkimpy still fails. rspamd's file-scan DKIM symbol is absent after those hops.
- Roundcube 1.6.19 shows that mutant as Author `author@lab.test`. SnappyMail 2.38.2 shows it as Attacker `attacker@evil.test`. Screenshots are in `clients/`.
- OpenDMARC 1.4.2 records `header.from=lab.test` for the single From and `header.from=evil.test` when Attacker is the first From. Both messages were delivered. Lab DNS SPF is `v=spf1 -all` and DMARC is `p=none`, so both SPF and DMARC results are fail under that overlay.
- OpenDKIM 2.11.0 (`USE_UNBOUND`) wrote `dkim=fail reason="key not found in DNS"` for the legitimate signature and for the mutant. `dig` against `10.88.0.53` returns the `cal._domainkey.lab.test` TXT. The DNS log has no query from the OpenDKIM container for that name, including after a local forwarder was placed in front of its resolver. This is not a signature pass/fail comparison.
- Week-4 minimization kept the DKIM-Signature bytes and re-verified the frequent status classes. The `dkimpy=fail / perl=pass / go=pass / rspamd=fail` class is the same inserted From. Reverting that one inserted line removes the split. No status class outside the week-2 matrix remained.
- Exim 4.92 #5, built 04-Jan-2024, stored one Mailpit message for the existing I1 CRLF payload and one for the LF payload. The CRLF dialogue then returned `554 SMTP synchronization error`. The LF payload left the injected SMTP text in that single body. Envelope sender stayed `alice@sender.lab.test`.
- Three immediate repeats of the library mutant stayed `dkimpy=fail`, `perl=pass`, `go=pass`, `rspamd=fail`.

- w2/w3 增量（研究网栈）：OpenDMARC U-label 空洞的评估器分裂与执行翻转、rua 报告空洞、显示层 Unicode 品牌归一化（5 张截图）、repair matrix（单跳性质过异构中继）、recfuzz2+diffrun 八形态×三 MTA 语法矩阵与 parser 三列、sigprobe2 的 obs 注入×中继×验证器九格（修复消除/传播验证分裂）。汇总见 `results/research/SYNTHESIS.md`。

## What it does not support

These selection and oversign behaviors are the RFC 6376 section 3.5 and section 5.4.2 mechanisms, in the same family as the composition failures in Chen, Paxson, and Jiang (USENIX Security 2020). They are not reported here as a new vulnerability. The client difference is which From instance each program displays. Lab DNS used DMARC `p=none`. No Gmail or Exchange measurement was done. OpenDKIM did not retrieve the published key, so this run does not say how OpenDKIM treats the duplicate From once the key is in hand.

OpenDKIM 列因公钥检索仪器问题缺失；parsedmarc 报告消费端未验证（离线装包受阻）；无 Gmail/Exchange 等真实服务测量；U-label 核心已被 CVE-2026-100891 覆盖（本实验室为独立复现，增量见 w2 UPSTREAM.md）。

## Disclosure draft (not sent)

No vendor has been contacted. The draft in `DISCLOSURE_DRAFT.md` is not a notice. `report/gate.json` keeps `disclosure_sent: false`.
