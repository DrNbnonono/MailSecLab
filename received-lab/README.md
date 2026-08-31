# received-lab

第一阶段:搭建一个**完全隔离的本地 SMTP 实验链**,专门用来研究 `Received:` 头的增长行为,暂时不引入 SPF / DKIM / DMARC。

## 1. 拓扑与设计目标

```
Swaks / Python (client)
        │
        ▼
    Postfix-1  ──►  Postfix-2  ──►  Postfix-3  ──►  Mailpit
```

- 全部跑在 Docker 的内部网络 `mailnet` 里,**不向公网发送邮件**。
- 只把 Mailpit 的 Web UI 端口 `127.0.0.1:8025` 暴露给宿主;三个 Postfix 的 25 端口只在容器之间可见。
- 链路中**没有** Dovecot / Rspamd / OpenDKIM / ClamAV / Bind9 等组件,避免无关变量干扰 `Received:` 实验。

研究目标集中在四件事:

```text
SMTP  +  Received  +  MTA forwarding  +  loop detection
```

---

## 2. 宿主前置条件

平台为 Windows 时,推荐这一层结构:

```
Windows
└── WSL2 Ubuntu 22.04 / 24.04
    └── Docker Desktop
        └── received-lab
```

先在 WSL Ubuntu 中确认:

```bash
docker --version
docker compose version
```

Docker Desktop 安装后,需要开启 WSL 集成:

```
Docker Desktop
  → Settings
  → Resources
  → WSL Integration
  → 开启你的 Ubuntu
```

**以下所有命令都在 WSL Ubuntu 中执行。**

---

## 3. 目录结构

```bash
mkdir -p ~/received-lab
cd ~/received-lab

mkdir postfix
mkdir client
mkdir scripts
```

最终:

```text
received-lab/
├── docker-compose.yml
├── postfix/
│   ├── Dockerfile
│   └── entrypoint.sh
└── client/
    └── Dockerfile
```

可用 `tree` 查看;若没有可 `sudo apt install tree`。

---

## 4. 组件文件

### 4.1 Postfix 镜像 —— `postfix/Dockerfile`

基于 `debian:bookworm-slim`,只装 `postfix` 和 `ca-certificates`,入口脚本来自 `entrypoint.sh`。

### 4.2 Postfix 启动脚本 —— `postfix/entrypoint.sh`

用 `postconf -e` 在容器启动时按环境变量注入配置。关键点:

| 配置项                  | 默认值 / 说明                                          |
| -------------------- | -------------------------------------------------- |
| `myhostname`         | 取自环境变量 `MYHOSTNAME`                              |
| `inet_interfaces`    | `all`,只走 IPv4(`inet_protocols = ipv4`)            |
| `mynetworks`         | `0.0.0.0/0`(容器内网专用,不是公网暴露)                   |
| `mydestination`      | 留空——本节点只做中继,不做本地投递                          |
| `smtpd_relay_restrictions` | `permit_mynetworks,reject_unauth_destination` |
| `smtp_tls_security_level`  | `none`(实验阶段不引入 TLS 变量)                 |
| `smtpd_tls_security_level` | `none`                                     |
| `hopcount_limit`     | 取自 `HOPCOUNT_LIMIT`,默认 `50`(**核心可调参数**)       |
| `header_size_limit`  | 取自 `HEADER_SIZE_LIMIT`,默认 `102400`               |
| `relayhost`          | 可选,只在 `RELAYHOST` 非空时设置                       |

入口脚本最终 `exec postfix start-fg` 前台运行,容器日志会打印:

```text
Postfix starting
Hostname:        <MYHOSTNAME>
Relayhost:       <RELAYHOST 或 空>
Hop count limit: 50
```

### 4.3 实验客户端 —— `client/Dockerfile`

同样基于 `debian:bookworm-slim`,安装:

- `swaks` —— SMTP 构造工具
- `python3` —— 自定义 SMTP / Received 注入脚本
- `netcat-openbsd` —— 手工调试 SMTP 协议
- `curl` / `dnsutils` —— 抓包 / DNS 查询

容器默认 `CMD ["sleep", "infinity"]`,通过 `docker exec` 进入。

### 4.4 编排 —— `docker-compose.yml`

5 个服务,全部接入 `mailnet`(bridge):

| 服务          | 关键环境变量 / 端口                                       |
| ----------- | -------------------------------------------------- |
| `postfix1`  | `MYHOSTNAME=postfix1.lab.test`,`RELAYHOST=[postfix2]:25`,`HOPCOUNT_LIMIT=50` |
| `postfix2`  | `RELAYHOST=[postfix3]:25`                          |
| `postfix3`  | `RELAYHOST=[mailpit]:1025`                         |
| `mailpit`   | `axllent/mailpit:latest`,只暴露 `127.0.0.1:8025:8025`     |
| `client`    | `hostname=client.lab.test`,挂载 `./scripts:/scripts`    |

**只有 Mailpit 的 8025 端口对外开放,三个 Postfix 的 25 端口一律留在容器网络内。**

---

## 5. 构建与启动

```bash
docker compose build      # 首次会拉 debian 基础镜像与 mailpit
docker compose up -d
docker compose ps         # 期望 5 个服务全部 Up
```

验证关键配置:

```bash
docker logs postfix1                                 # 看启动横幅
docker exec postfix1 postconf hopcount_limit         # → hopcount_limit = 50
docker exec postfix1 postconf relayhost              # → relayhost = [postfix2]:25
docker exec postfix2 postconf relayhost              # → relayhost = [postfix3]:25
docker exec postfix3 postconf relayhost              # → relayhost = [mailpit]:1025
```

---

## 6. 第一个里程碑:基线邮件验证

进入客户端容器:

```bash
docker exec -it mail-client bash
```

发一封基线邮件:

```bash
swaks \
  --server postfix1 \
  --port 25 \
  --from alice@sender.lab.test \
  --to bob@receiver.lab.test \
  --header "Subject: Received Baseline Test" \
  --body "Hello Received header."
```

正常时返回 `250 2.0.0 Ok: queued as ...`。

浏览器打开 `http://localhost:8025`,点进 `Received Baseline Test`,在 `Source` / `Raw` / `Headers` 视图里确认:

```text
Received: from postfix2.lab.test    by postfix3.lab.test ...
Received: from postfix1.lab.test    by postfix2.lab.test ...
Received: from client.lab.test      by postfix1.lab.test ...
```

**头部顺序:** 最新的在最上面 —— `Postfix-3 → Postfix-2 → Postfix-1`。

> 这就是**实验 0:正常增长行为**。链路搭通的判定标准:每经过一个 Postfix,顶部就多出一个 `Received:`。

---

## 7. 调参提示

- 实验早期(扫描 `N = 0 ~ 51` 临界)建议把 `HOPCOUNT_LIMIT` 下调到 `8`,只需改 `docker-compose.yml` 三个服务的环境变量,然后 `docker compose down && docker compose up -d --build`。
- 正式跑大批量数据时再恢复 `50`。
- 每次实验建议同时保存:原始邮件、`postfix1/2/3` 的 `docker logs`、Mailpit 中的最终 Raw Message。
