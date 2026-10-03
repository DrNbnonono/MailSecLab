# parsedmarc 报告消费端探针（任务 9c，w3）

parsedmarc 11.0.3（msl-verifiers，cp311 离线 wheel 安装），`parse_aggregate_report_xml(offline=True)` 直喂三份 XML：

| case | 内容 | 结果 |
| --- | --- | --- |
| legit | 结构完好报告：receiver.example → xn--mnchen-3ya.bank.test（p=reject 与 DNS 一致），行数据对应实验室真实观测（10.88.0.11×3，dkim/spf fail，disposition=none） | **摄入**，字段全部还原 |
| forged | **攻击者捏造**：冒名 org_name=`Google, Inc.` / `noreply-dmarc-support@google.com`，report_id 仿造格式；行数据全捏造（source_ip=198.51.100.66、count=5000、声称收件方 disposition=none 全放行）——从未有任何真实接收方发出 | **摄入，零来源校验**：org/email/count/source_ip 全部进入消费端数据模型 |
| broken | w2 手工 reference-aggregate（date_range=0 占位） | **拒收**（`InvalidAggregateReport: Missing field: 'report_id'`）——结构校验存在 |

## 结论

- **消费端做结构校验、不做来源认证**：伪造的聚合报告（冒名任意 reporter、任意行数据）被事实标准开源消费端 parsedmarc 无条件摄入。RFC 7489/9989 聚合报告本身无认证机制（纯邮件投递），消费端也不补——两者叠加构成**监控数据的投毒面**：受害者域名主的 DMARC 看板上可被注入任意「伪造来源 IP × 任意量级 × 任意处置结论」。
- 与 w2 rua 盲区（发送侧空洞）合拢成完整叙事：**发送侧看不见该看的（U-label 事件永远不进报告），消费侧照单全收不该收的（无认证的伪造报告）**——监控生态完整性缺口的两半都已在实验室测得。
- 诚实边界：XML 级摄入；真实部署中报告经邮件/压缩包投递，parsedmarc 的邮件路径同样无认证要求（DKIM/SPF 不校验 reporter），但未在本实验单独测邮件路径。攻击前提是攻击者能向受害者的 rua 收件地址投信（公开 DNS 可查）。

证据：`parsedmarc-probe/{legit,forged,broken}.xml`、`probe.json`、`verdict.json`（`legit: true, forged: true, origin_verification_seen: false`）。

## 过程记录

- wheel 落点事故：用户在有网机器执行下载时 shell 吞了 Windows 路径反斜杠，49 个 wheel 落在 `received-lab/E:MailSecLabreceived-labresearchwheels/`，已归位到 `research/wheels/`（现 80 个文件，cp311+cp313 并存）。
- API 修正：parsedmarc 11 无 `parse_report_xml`，正确入口 `parse_aggregate_report_xml(..., offline=True)`；结果为 pydantic 模型（`model_dump()`），字段名 `org_email`/`records[].source.ip_address`。
