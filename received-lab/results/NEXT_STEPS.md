# K 系列实验计划 — 认证层解释差分（2026-09-07 制定）

**研究主线回顾**：Received 无限增长（Phase1/2、E）→ 限制面测绘（E/F/G）→ 信任边界
（H）→ 协议级走私/链伪造（I）→ 单验证器 DKIM 交互（J）。
**已确立**：transport ≠ parser ≠ security view 的三方分歧在传输层（3B/E3）、
解析层（3C）、安全层（H/F1）均有实证；J 系列发现 dkimpy 在畸形头上"拒绝解析"
（签名后无法验证）—— 但这只是一家验证器的行为。

## K 系列核心问题

> **同一个 DKIM 签名（同字节、同密钥），在不同验证器眼里是否存在、是否有效？**

这是"解释差分"研究线的最后一块：验证器差分。若成立，攻击者可获得
"签名在过滤系统 A 有效、在系统 B 不存在"的新型欺骗原语。

## 实验设计

### K0 · 基础设施：三验证器工具链 + （可选）本地权威 DNS

三个异构 DKIM 验证器（刻意选不同实现语言/年代）：

| 验证器 | 语言/年代 | 引入方式 |
| --- | --- | --- |
| dkimpy 1.1.8 | Python | 已有（client 容器） |
| OpenDKIM 2.11 | C（milter 时代，宽松解析传统） | 新容器（bookworm apt） |
| go-msgauth dkimverify | Go（emersion，现代实现） | 新容器（parsers/go 基础镜像 + go install） |

### K1 · 验证器边界差分矩阵（核心实验）

语料（全部字节级固定 + sha256）：
- 既有：V001–V012 corpus、j1_stored（截断后）、j2_appended（l= 追加）、j3_injected/stored（淹没）
- 新增 KB 系列：
  - KB1 干净签名（对照）
  - KB2 签名后注入异常头（dkimpy 已证明拒绝解析 —— 看另外两家）
  - KB3 重复 From/Subject（验证器选第一个还是最后一个 → i=/DMARC 对齐差异）
  - KB4 头区在正文之后再出现（第二头块；宽松解析器可能接受）
  - KB5 l= 截短 + 追加区含头状行
- 每条经三验证器，记录：pass / fail / refuse-to-parse（以及用到的 From 实例）

**假设**：H1（边界差分）KB2/KB4 上至少一对验证器结果不一致；
H2（选择差分）KB3 上 From 选取不同。

### K2 · l= 武器化端到端（承接 J2）

KB5 + j2_appended 在三验证器上：l= 是否被一致遵守；追加的第二头块是否被任何
验证器当作头参与验证（签名/正文边界错位）。

### K3 · rspamd 全栈接入（高价值、有稳定性风险）

前置 canary：rspamd 3.4 的 exit-255 归因（maps.rspamd.com 在线刷新）置信度中等
—— H 系列只证明了 network:none 稳定。本步先做 15 分钟 canary：
`extra_hosts: maps.rspamd.com→127.0.0.1`（刷新变 instant-refused）观察是否仍崩溃；
仍崩则放弃 rspamd DNS 栈，K3 降级为可选项。
通过后：
- dnsmasq 容器做 lab.test 权威 DNS（DKIM TXT / SPF / DMARC 记录）
- compose 给 rspamd 配 `dns:`；修复 h_ip.lua 的正式注册（rspamd.conf `.plugins` 段，
  H 系列遗留）
- 将 H（伪造 source）+ J（淹没/l=）语料全量过 rspamd，记录 R_DKIM_*/DMARC_*/SPF_*
  符号与 derived IP 的联判

### K4（拉伸）· DMARC From 对齐的歧义利用

KB3/KB2 在 rspamd（依赖 K3）下的 RFC5322.From 选取：From "沉入正文"或重复时，
DMARC 对齐用哪个？能否构造"签名有效域 ≠ 展示 From 域"的报文。

### K5（可选）· 走私阳性对照

Exim 4.92（buster 时代）容器，验证 I 系列方法能复现已知 CVE-2023-51764——
补齐方法论严谨性。优先级最低，时间盒半天。

## 新增 Docker 环境（安装命令）

```bash
cd ~/received-lab   # WSL 内 /mnt/e/MailSecLab/received-lab

# 1) OpenDKIM 验证器
mkdir -p opendkim && cat > opendkim/Dockerfile <<'EOF'
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy \
 && apt-get update && apt-get install -y opendkim opendkim-tools ca-certificates \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep","infinity"]
EOF

# 2) go-msgauth 验证器（复用 parsers/go 的代理式构建）
mkdir -p parsers/go-msgauth && cat > parsers/go-msgauth/Dockerfile <<'EOF'
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy \
 && apt-get update && apt-get install -y golang-go ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV GOPROXY=http://172.29.112.1:17892 \
    GOFLAGS=-insecure
RUN go install github.com/emersion/go-msgauth/dkim/cmd/dkimverify@latest \
 && ln -s /root/go/bin/dkimverify /usr/local/bin/dkimverify
CMD ["sleep","infinity"]
EOF

# 3) dnsmasq 权威 DNS（K3，通过 canary 后再做）
mkdir -p dns && cat > dns/Dockerfile <<'EOF'
FROM debian:bookworm-slim
RUN printf 'Acquire::http::Proxy "http://172.29.112.1:17892";\n' > /etc/apt/apt.conf.d/95proxy \
 && apt-get update && apt-get install -y dnsmasq && rm -rf /var/lib/apt/lists/*
CMD ["dnsmasq","--no-daemon","--log-queries"]
EOF
# compose 片段（挂到 mailnet，rspamd 加 dns: 指向它）：
#   dns:
#     build: { context: ./dns, network: host }
#     networks: [mailnet]
#     profiles: ["k3"]

# 全部照旧：构建期走 portproxy 代理 + network: host
# docker compose --profile k1 up -d --build   # (opendkim/go-msgauth 归入 k1 profile)
```

## 风险与预案

| 风险 | 预案 |
| --- | --- |
| rspamd 开网后复现 exit-255 | K3 前置 canary；失败则 K3/K4 降级，主线 K1/K2 不受影响 |
| OpenDKIM 无独立 CLI 验证入口 | 用 `opendkim-testmsg`（opendkim-tools 提供）；不行则 milter 模式挂 postfix |
| go install 被墙 | GOPROXY 走 portproxy；再不行退化为第二个 Python 实现（authres）做弱对照 |
| 语料缺陷重演（G 系列教训） | 每个 KB 生成后强制结构自检（头行数/双 CRLF/首头前无空行），三 parser 交叉 |

## 交付物

- `results/k-series/RECORD.md` + `k1_matrix.csv`（语料 × 验证器 × 结果）
- 报告 §16；若 H1/H2 成立，补一张"验证器差分"热力图
- 结论并入"transport ≠ parser ≠ verifier ≠ security"四层分歧总图

## 暂缓项（记录在案）

- 走私矩阵版本扩展（K5，半天时间盒）
- 邮件客户端渲染差分（需 GUI 自动化，与本实验室栈不匹配）
- 真实互联网测量（涉及第三方扫描，超出隔离实验范围）
- digest pin 还原（等代理恢复）
