# MailSecLab 八周研究执行计划

批准日期：2026-10-01。用户已批准完整路线、隔离新增组件、受控语料和仅准备披露材料。

**目标**：检验邮件接收、修复、认证和展示之间的字段身份绑定，形成根因、安全后果、方法消融和防御证据。目标会议为 USENIX Security、IEEE S&P、CCS、NDSS，不保证发现或录用。

**架构**：独立 Compose 项目 mailseclab-research；内部网络；保留旧容器、旧邮件和历史结果。Python 标准库负责不可覆盖证据、原始结构检查、固定签名变异、SMTP/HTTP 采集。DKIM 库在独立镜像中执行。所有网络发信均限本地实验网络。

## 执行清单

- [x] 第1周：历史/维护环境清单、四家验证器正负对照、适配器字节与精确 DNS 校准、G4/I2 补证。
- [x] 第2周：From/Subject/Message-ID 独立系列；simple/relaxed、relaxed/relaxed；单实例签后前后插入，双实例签后改首/末、反转、删除；h=一次/全部/全部+一次；变异不重新签名；源码诊断与参考哈希。
- [ ] 第3周：Postfix+rspamd、Postfix+OpenDKIM/OpenDMARC，两条 Milter 链接 Dovecot；本地 SPF/DMARC；Roundcube/SnappyMail DOM/截图；攻击者密钥权限隔离。客户端和 OpenDMARC 的 header.from 已记录。OpenDKIM 2.11.0 没有向实验室 DNS 查询公钥，DKIM 行是 key not found，签名差分未完成。
- [x] 第4周：字节/语法/静态差分/链路差分四臂；相同初始种子0—4，各60分钟，最多两进程；候选排序、每类前十、保持签名与后果的最小化。
- [x] 第5周：冻结维护版本；OSMTPD→PF、OSMTPD→Exim、Exim→PF、PF→Exim、OSMTPD→OSMTPD；有限环220转发或60秒；Exim4.92仅阳性对照。
- [x] 第6周：现有防御、身份歧义拒绝、认证绑定/失效；一万封受控兼容邮件，家族隔离开发/保留集；每轮100预热+500测量，三轮。
- [x] 第7—8周：重建后三次复现；最近邻机制对照；论文骨架、图表、重放包与未发送披露草稿。

## 路径与接口

新增代码限 received-lab/research/；结果限 received-lab/results/research/<run-id>/。入口 python3 research/run.py --stage bootstrap|causal|e2e|fuzz|defense|report --run-id <id>。

每个对象保留raw和SHA-256；SMTP、最终投递、验签、策略分别记录。保存字段字节范围、边界、DNS、退出码、标准错误、客户端身份。区分pass/fail/none/parse-error/policy-reject/temp-error/timeout/tool-error及pending。

控制CPU≤4核、内存≤5GiB、产物≤20GiB；UI仅localhost 18025/18080/18081。构建允许下载，实验运行不出公网。缺失前置条件拒绝执行，不将工具失败记作阴性。

## 验收与停止

校准未通过不进入解释性实验。第二周每类分歧必须有固定签名最小对象和根因。第四周若既无新机制也无可重复方法收益，收束报告并停止昂贵扩展；不自动切换真实邮件课题。负结果保留，重复样本不计独立发现。没有用户授权不联系厂商、不公开发布、不发送公网邮件。

## 实现顺序

1. 先执行 unittest 验证原始结构、bottom-up字段覆盖、签名不变、证据防覆盖、DNS范围和阶段门槛；实现后重跑。
2. 构建工具/验证器镜像，检查 compose 内部网络、资源和端口；启动新栈并跑校准。
3. 固化bootstrap结果；运行causal并审查根因。
4. 校准两条真实认证链；接入后续方法、防御与报告流程。

执行中按结果更新状态，不把尚未运行的阶段写成已完成。现有用户修改不回退；不提交混有其他修改的commit。
