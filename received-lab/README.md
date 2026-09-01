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

---

## 8. 手动复现命令手册

> 所有命令都在 **WSL Ubuntu**、`received-lab` 项目根目录下执行(本机实际路径为 `/mnt/e/MailSecLab/received-lab`)。
> 实验结论与数据详见 `results/REPORT.md`;本节只列"敲哪些命令、看到什么算对"。

### 8.0 环境自检与启动

```bash
cd /mnt/e/MailSecLab/received-lab

docker compose ps                              # 5 个容器应全部 Up
docker exec postfix1 postconf mail_version     # 3.7.11
for h in postfix1 postfix2 postfix3; do
  docker exec $h postconf hopcount_limit relayhost
done
# 期望:50 / [postfix2]:25 、 50 / [postfix3]:25 、 50 / [mailpit]:1025

docker logs postfix1 2>&1 | tail -5            # 应能看到 postfix/smtpd、qmgr 等运行日志
# 若只有启动横幅没有运行日志,说明镜像还是旧 entrypoint,执行:
#   docker compose up -d --build postfix1 postfix2 postfix3

# 浏览器打开 Mailpit:http://localhost:8025
# 实验前清空邮箱(强烈建议,避免旧消息干扰投递判定):
docker exec mail-client python3 /scripts/check_delivery.py --clear
```

### 8.1 里程碑:基线邮件 + 预置 Received

```bash
# ① 基线邮件(client -> P1 -> P2 -> P3 -> Mailpit)
docker exec mail-client swaks --server postfix1 --port 25 \
  --from alice@sender.lab.test --to bob@receiver.lab.test \
  --header "Subject: Received Baseline Test" --body "Hello Received header."
sleep 2

# 看最终报文:应有 4 条 Received(3 条 Postfix + 1 条 Mailpit),顺序最新在最上
docker exec mail-client python3 /scripts/check_delivery.py \
  --dump-subject 'Received Baseline Test' | head -25

# ② 预置 10 个伪造 Received:应投递,最终 14 条(10+3+1)
docker exec mail-client python3 /scripts/send_received.py -n 10 --case-id M010
sleep 1
docker exec mail-client python3 /scripts/check_delivery.py --case-id M010 --timeout 10
```

### 8.2 实验一:hopcount 边界扫描(limit = 50)

`scan.sh <输出csv> <起始N> <结束N> [头名] [用例前缀]`,自动记录 SMTP 回复、三个 Postfix 的日志取证、Mailpit 最终 Received 数,并保存每用例证据到 `results/logs/<case>.*`。

```bash
docker exec mail-client python3 /scripts/check_delivery.py --clear
rm -f results/scan_limit50.csv                 # 想重跑时先删旧 CSV(存在则追加)
bash scripts/scan.sh results/scan_limit50.csv 0 49
bash scripts/scan.sh results/scan_limit50.csv 50 100

column -t -s, results/scan_limit50.csv | less -S   # 逐行查看
awk -F, 'NR>1{print $9}' results/scan_limit50.csv | sort | uniq -c
# 期望:47 delivered / 2 bounced_not_delivered / 52 rejected_at_data(554)
```

预期临界行为:

| N | 现象 |
| --- | --- |
| ≤ 46 | 投递,最终 Received = N+4 |
| 47 | P3 拒绝(hopcount exceeded),P2 生成退信,退信进 Mailpit |
| 48 | P2 拒绝,P1 生成退信 |
| ≥ 49 | P1 在 DATA 阶段直接回 `554 5.4.0 Error: too many hops`,客户端当场看到 |

### 8.3 交叉验证:hopcount_limit 临时调到 8

运行时修改,不动 compose 文件,实验后必须恢复:

```bash
for h in postfix1 postfix2 postfix3; do
  docker exec $h postconf -e 'hopcount_limit = 8'
  docker exec $h postfix reload
done
docker exec postfix1 postconf hopcount_limit        # 应显示 8

docker exec mail-client python3 /scripts/check_delivery.py --clear
rm -f results/scan_limit8.csv
bash scripts/scan.sh results/scan_limit8.csv 0 12
# 期望:N≤4 投递(N+3≤7);5 → P3 拒;6 → P2 拒;≥7 → P1 DATA 554

# 恢复
for h in postfix1 postfix2 postfix3; do
  docker exec $h postconf -e 'hopcount_limit = 50'
  docker exec $h postfix reload
done
docker exec postfix1 postconf hopcount_limit        # 应显示 50
```

### 8.4 实验二:头字段名变体

```bash
docker exec mail-client python3 /scripts/check_delivery.py --clear
bash scripts/scan.sh results/variants_xreceived.csv   100 100 'X-Received'    XR
bash scripts/scan.sh results/variants_receivedspf.csv 100 100 'Received-SPF'  RS
bash scripts/scan.sh results/variants_case_mixed.csv  46  47  'rEcEiVeD'       RC
bash scripts/scan.sh results/variants_case_upper.csv  46  47  'RECEIVED'       RD
```

期望:X-Received / Received-SPF ×100 投递且 Received 仍为 4(不参与计数);两种大小写变体在 46/47 的行为与标准 Received 完全一致(大小写不敏感计数)。注意:变体 CSV 里 `final_received_count` 只精确统计 `Received:`,变体头要用 `inspect_raw.py` 看(见 8.7)。

### 8.5 实验三:真实邮件循环(P3 → P1)

```bash
bash scripts/loop_test.sh
# 脚本自动:改 P3 relayhost 指回 P1、limit=8、发 LOOP01、等 25s、
#           存证据到 results/loop/、然后用 compose restart 恢复拓扑
tail -30 results/loop/LOOP01.p1.log | grep -E 'hopcount|status='
# 期望:原邮件绕到第 8 跳被拒(554 too many hops),退信(DSN)自绕一圈同样死亡,
#       空发件人不再生成二次退信,Mailpit 全程零收到
```

想手动逐步操作的话:

```bash
for h in postfix1 postfix2 postfix3; do
  docker exec $h postconf -e 'hopcount_limit = 8'; docker exec $h postfix reload
done
docker exec postfix3 postconf -e 'relayhost = [postfix1]:25'; docker exec postfix3 postfix reload

docker exec mail-client python3 /scripts/send_received.py -n 0 --case-id LOOPMANUAL
sleep 15
docker logs postfix1 2>&1 | grep -E 'hopcount|status=' | tail -15

docker compose restart postfix1 postfix2 postfix3   # 务必恢复!
```

### 8.6 第二阶段:RFC 无界增长路径

```bash
docker exec mail-client python3 /scripts/check_delivery.py --clear
rm -f results/phase2.csv
bash scripts/phase2.sh          # 16 个固定用例:B/C/D/E/F + 边界控制,写 results/phase2.csv
column -t -s, results/phase2.csv | less -S
```

想单独手动发某一类报文(发完用 8.7 的命令观察):

```bash
docker exec mail-client python3 /scripts/send_received.py --style resent -n 100 --case-id MYRESENT   # Resent 块,hopcount 无感
docker exec mail-client python3 /scripts/send_received.py --style arc    -n 100 --case-id MYARC     # ARC 三元组
docker exec mail-client python3 /scripts/send_received.py --style folded -n 3 --fold-kb 90 --case-id MYFOLD   # 90KB 折叠巨头
docker exec mail-client python3 /scripts/send_received.py --style folded -n 1 --fold-kb 150 --case-id MYBIG   # 超 header_size_limit → 静默截断
docker exec mail-client python3 /scripts/send_received.py --header-name Subject    -n 50 --case-id MYSUBJ     # 重复 max-1 字段
docker exec mail-client python3 /scripts/send_received.py --header-name 'Received ' -n 100 --case-id MYSPACE  # 空格变体 → 会被计数,554
docker exec mail-client python3 /scripts/send_received.py --header-name 'Receíved'  -n 50  --case-id MYUTF8  # UTF-8 同形 → 不计数,但头部区被终结
docker exec mail-client python3 /scripts/send_received.py -n 46 --extra-count 100 --extra-name X-Received --case-id MYRW   # 垃圾头不移动边界
```

### 8.7 取证与观察命令速查

```bash
# 某用例是否投递 / 有无退信 / 最终 Received 数
docker exec mail-client python3 /scripts/check_delivery.py --case-id <CASE> --timeout 10

# 导出某封邮件的原始报文
docker exec mail-client python3 /scripts/check_delivery.py \
  --dump-subject 'Received Baseline Test' > results/my_raw.eml

# 报文结构取证:严格/空格/UTF-8 Received 各多少(头区 vs 正文)、
# 任意字段名计数(--name 可重复)、总头数、最大单头字节
docker exec mail-client python3 /scripts/inspect_raw.py --case-id <CASE> \
  --name Received --name Resent-Date --timeout 10

# 三节点日志与队列
docker logs postfix1 2>&1 | tail -20
docker logs postfix1 2>&1 | grep -E 'hopcount|status=' | tail -10
docker exec postfix1 postqueue -p          # 卡队列时看 deferred 及原因
```

### 8.8 环境重置

```bash
# 只恢复配置(entrypoint 会按环境变量重写 main.cf):
docker compose restart postfix1 postfix2 postfix3

# 彻底重来(清队列、重建容器;镜像改动后才需要 --build):
docker compose down && docker compose up -d --build
docker exec mail-client python3 /scripts/check_delivery.py --clear
```

### 8.9 结果速查表(用于人工核对)

| 实验 | 期望结果 |
| --- | --- |
| 基线 | 4 条 Received,顺序 Mailpit→P3→P2→P1(新在上) |
| 预置 N=10 | 投递,最终 14 条 |
| limit=50 扫描 | 47 投递 / 2 退信(47:P3 拒、48:P2 拒)/ ≥49 全部 DATA 554 |
| limit=8 扫描 | N≤4 投递 / 5:P3 拒、6:P2 拒 / ≥7 DATA 554(边界随 limit 线性缩放) |
| X-Received / Received-SPF ×100 | 投递,Received 仍 4 |
| rEcEiVeD / RECEIVED 46/47 | 与标准 Received 边界完全一致 |
| 循环 | 第 8 跳 hopcount 终止,DSN 自绕一圈后由空发件人规则终结,Mailpit 零收到 |
| Resent ×300 / ARC ×100 / Subject ×50 | 全部投递,hopcount 无感 |
| 折叠 150KB 单头 | 投递,单头被截断至 ~101701B |
| `Received :` ×100 | 554(规范化后计数) |
| `Receíved:` ×50 | 投递,不计数;后续合法头被降级为正文 |

### 8.10 Phase 3A:跨版本差分(Postfix 3.7.11 vs 3.11.6)

```bash
# 启动 PF11 链(postfix1n/2n/3n,debian:sid → Postfix 3.11.6)
docker compose --profile pf11 up -d --build
docker exec postfix1n postconf mail_version                          # 3.11.6
docker exec postfix1n postconf -d non_empty_end_of_header_action     # 默认 fix_quietly

# 构建/校验字节级 corpus(V001~V012,含 sha256 manifest)
docker exec mail-client python3 /scripts/build_corpus.py --out /results/phase3/corpus

# 全矩阵:PF37×default + PF11×{default,fix_quietly,add_header,reject}(约 4 分钟)
bash scripts/phase3.sh
bash scripts/phase3.sh pf37        # 或只跑某一轮
column -t -s, results/phase3/matrix.csv | less -S
# 期望:两版本 default 下 12 用例行为完全一致;add_header 下 V007~V009 多出 1 个
#       MIME-Error 头;reject 下 V007~V009 被 P1 以 550 5.6.0 拒绝;V002/V003 的
#       hopcount 边界与 V012 的 101700B 截断在所有轮次一致

# 手动单发某个 corpus 用例并取证
docker exec mail-client python3 /scripts/send_received.py \
  --server postfix1n --input-file /results/phase3/corpus/V007.eml
docker exec mail-client python3 /scripts/inspect_raw.py --case-id V007 \
  --name Received --name MIME-Error
docker exec mail-client python3 /scripts/check_delivery.py --case-id V007

# 手动切换 header-termination 策略(仅 3.11+;实验后务必还原)
docker exec postfix1n postconf -e 'non_empty_end_of_header_action = reject'
docker exec postfix1n postfix reload
# ……实验后还原:
docker exec postfix1n postconf -X non_empty_end_of_header_action
docker exec postfix1n postfix reload
```
