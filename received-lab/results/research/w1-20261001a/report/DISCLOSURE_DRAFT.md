# Disclosure draft (not sent)

No vendor has been contacted. This file is not a notice and has not been sent.

If a later run shows a consequence beyond RFC 6376 instance selection, a notice would name the versions below, attach the fixed-signature mutant, and describe what each program displayed. The evidence in this run does not support that notice.

Versions observed here:

- dkimpy 1.1.8, perl Mail::DKIM, go-msgauth 0.6.8, rspamd 3.4
- Roundcube 1.6.19 and SnappyMail 2.38.2
- OpenDKIM 2.11.0 and OpenDMARC 1.4.2
- Exim 4.92 #5 built 04-Jan-2024, as a local positive-control image only

The mutant is `causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml`. Its SHA-256 is in that case's `case.json`. On this object, perl and go-msgauth pass, dkimpy and rspamd fail, Roundcube displays Author, and SnappyMail displays Attacker. OpenDMARC's `header.from` is `evil.test`. OpenDKIM reported that the key was not found in DNS; the lab resolver did publish it.

## 披露候选清单（2026-10-03 w3 更新，均未发送）

### 候选 A：rspamd 群组/domain-literal From 的 DMARC 静默
- 证据链：w2 void/v1-v8 + hdrfuzz3 千例（117+139 例统计支撑）+ exec z 系列链上符号缺失；OpenDMARC 同信正常 fail——分裂完整。
- 上游核查：CVE-2026-100891 原文未覆盖（其 rspamd 对照是 U-label 转换正确）；rspamd GitHub issue 需按 weitongli 流程再查群组语法条目。
- 建议：hold——先补 rspamd 上游 issue 检索与最新版（3.4 之后）复测，再决定 send。

### 候选 B：外域 authserv-id 伪造 AR 存活 + SnappyMail 无校验绿徽章
- 证据链：w2 arsurv b1（DOM 节点 iconcolor-green + 截图）+ hdrfuzz3 千例（630/630 外域存活、0/157 本域）；RFC 8601 §5 要求边界删除不可信 AR——OpenDMARC 只删本域 id。
- 上游核查：SnappyMail GitHub 搜 Authentication-Results 渲染相关 issue；CVE-2026-100891 无此覆盖。
- 建议：hold——Roundcube 对照（不显示认证状态）已在案，补一个第三方 webmail 再定级。

共同前提：按 PLAN 第 7-8 周纪律，未联系任何厂商前本清单保持 unsent；gate.json 的 disclosure_sent 保持 false。
