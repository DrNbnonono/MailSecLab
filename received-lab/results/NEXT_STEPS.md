# 实验进度与下一步方向（2026-09-05，E/F/G 系列完成后）

**研究问题**：Received 头能否无限制增长。
**全部实验记录**：`result/e-series/`、`result/g-series/`、`result/f-series/RECORD.md`（含两次事故与纠错全记录）。

## 已确立的结论链

1. **数量维度有界但非协议常数**：Postfix hopcount 50 / Exim received_headers_max 30 /
  OpenSMTPD 100，触发模式各异（内联 554 / 500；Exim 先收后退信）；F3 证明边界随配置线性移动。
2. **字节维度近乎无界**（G4 修正版 R3）：真折叠 X-Received 头块 9,096,191B 经三跳 Postfix
  链投递，Received 恒 4；约束仅 message_size_limit（~10.24MB）。
3. **计数盲区与通道宽度**：`Received<SP>:` 只对 OpenSMTPD 盲；G3 归因 —— Postfix 改写+计数、
  Exim 只计数不改写、OpenSMTPD 不计数但改写；通道宽度 = 连续无计数 MTA 跳数。
4. **放大**：loop-DSN 放大率 31.9×（空报文）→ ~1（大报文），圈数受数量上限闭环。
5. **安全组件视角**：WSP 通道产物被 rspamd 标 `BROKEN_HEADERS +8.0`（骗过传输计数骗不过
  解析器）；9MB 真头块对 rspamd 无压力（56ms / 3.4 分，G4 修正后结论）。  
   首轮 "rspamd 丢头" 结论因语料双 CRLF 缺陷撤回（详见 g-series/RECORD.md 纠错记录）。



## 下一步（按价值排序，H 系列完成后更新）

1. **链一致性判据的边界刻画**：H3 显示 rspamd 在"by/from 衔接断裂"处切断信任链 ——
  系统性测试哪些断裂被识别（helo 不匹配 / IP 不匹配 / 时间戳倒挂 / 缺失括号 IP），
   哪些伪造链形态仍能穿透（例如完全一致地伪造整条链 + 诚实中继继续 prepend）。
2. **DKIM l= 标签 × 头区边界**：Postfix 对 WSP 的改写、对超大折叠头的截断（header_size_limit）
  都会移动 l= 覆盖字节与验证者读取字节的相对位置 —— 用真实 signer/verifier 验证。
3. **Postfix cleanup 规范化的日志与开关**：WSP→Received 转正发生在 cleanup 哪个阶段、
  有无告警日志（对取证/检测有意义）。
4. **rspamd 9MB 报文的 source 提取补全**（h_ip 插件在 rspamd.conf 主配置注册的方式）；
  DNS 启用后 RDNS/HFILTER 判定复测。
5. 工程清理：代理恢复后还原 digest pin。

