# Stage-2 栈手术记录（w4-20261003a / gramfuzz，任务 6 Step 6.1）

日期：2026-10-03。目的：重放 w3 diffrun 的捕获路由，使三台中继都把
`capture@lab.test` 的信直接投进 msl-mailpit:1025（隔离末跳，存档即该 MTA
自身的输出）。**本任务不回滚——任务 7 campaign 继续使用本路由；跑完任务 7
后按下方回滚步骤恢复默认栈。**

依据：`w3-20261003a/diffrun/RECORD.md`「仪器记录」节 + `w2-20261002a/STATE.md`
「栈状态补充」节（w3 任务 7 收尾时已回滚，本次重放）。

## 改动清单（改动前均已备份到本目录）

### 1. exim（容器 `exim`，镜像 received-lab-exim:v3，双网）

- 文件：`/etc/exim4/exim4.conf`（编译期默认搜索路径，root:root 644）
- 改动（容器内 sed，保 root 属主——docker cp 会带源属主触发 exim 信任检查）：
  - `route_list = * msl-auth-postfix byname` → `route_list = * msl-mailpit byname`
  - transport `to_mailpit` 的 `port = 25` → `port = 1025`
- 生效：`docker restart exim`
- 备份：`exim4.conf.bak`
- 回滚：
  ```sh
  docker exec exim sed -i 's|route_list = \* msl-mailpit byname|route_list = * msl-auth-postfix byname|' /etc/exim4/exim4.conf
  docker exec exim sed -i 's|  port = 1025|  port = 25|' /etc/exim4/exim4.conf
  docker restart exim
  ```

### 2. opensmtpd（容器 `opensmtpd`）

- 文件：`/etc/smtpd.conf`（注意不是 /etc/mail/smtpd.conf，后者是旧副本）
- 改动：`action "to_mailpit" relay host smtp://msl-auth-postfix:25`
  → `action "to_mailpit" relay host smtp://msl-mailpit:1025`
- 生效：`docker restart opensmtpd`
- 备份：`smtpd.conf.bak`
- 回滚：
  ```sh
  docker exec opensmtpd sed -i 's|relay host smtp://msl-mailpit:1025|relay host smtp://msl-auth-postfix:25|' /etc/smtpd.conf
  docker restart opensmtpd
  ```

### 3. msl-auth-postfix（容器 `msl-auth-postfix`）

- 文件：`/etc/postfix/main.cf`；`/etc/postfix/transport`（文件 w2 起就在，内容
  `capture@lab.test smtp:[msl-mailpit]:1025`，本次未改文件，只重新挂上 map）
- 改动：`postconf -e "transport_maps = hash:/etc/postfix/transport"` +
  `postmap /etc/postfix/transport` + `postfix reload`
- 路由语义：transport_maps 按全址命中 capture@lab.test → smtp:[msl-mailpit]:1025；
  **bob@lab.test 不在 map 里，仍走 virtual_transport=lmtp:inet:msl-dovecot:24**
  （消费臂投递不受影响）。
- 备份：`postfix-main.cf.bak`、`postfix-transport.bak`、`postconf-before.txt`
- 回滚：
  ```sh
  docker exec msl-auth-postfix postconf -e "transport_maps ="
  docker exec msl-auth-postfix postfix reload
  ```

## 控制信验证（N=1，rcpt=capture@lab.test，ctl_verify.py）

| 目标 | SMTP | mailpit 取回 | 存档大小 |
| --- | --- | --- | --- |
| msl-auth-postfix | 250 2.0.0 Ok: queued as A3EB0744 | OK | 1004 B |
| exim | 250 OK id=1xCxG5-00000E-1L | OK | 799 B |
| opensmtpd | 250 2.0.0 01c1479f Message accepted for delivery | OK | 812 B |

CONTROL **PASS**。存档与 transcript 见本目录 `gf-surgery-ctl-*`。

## 其他

- WSL 保活（对 msl-client 每 15s 一次 docker exec 的循环，防 Docker Desktop
  resource-saver 停机，同 w2 STATE 做法）在 stage-2 smoke 期间运行，
  smoke 结束后已停止。**任务 7 campaign 前需重启**：
  ```sh
  while true; do docker exec msl-client true; sleep 15; done   # 后台跑
  ```
- 未删容器、未动镜像；只有 exim/opensmtpd 两个容器 restart 过，postfix 用 reload。
- 名字解析核对：exim/opensmtpd/msl-auth-postfix 三家 `getent hosts msl-mailpit`
  均为 10.88.0.25（研究网）。exim 的 route_list byname 在双网容器上按研究网
  地址命中（w2 曾有 mailnet 地址歧义教训，控制信存档 799 B 含 exim 自加
  Received，证明走的是 exim→mailpit 直连）。

## 手术下的实测（2026-10-03 stage-2 smoke，107 幸存者）

- 中继臂 107×3：postfix/exim 各 106 捕获、osmtpd 102（4 封被
  `550 5.7.1 ... not RFC 2822 compliant` 拒绝，1 封 corpus_check 门槛拦截）。
  存档标记核对（mailpit 自加 Received 的 from-clause）全部 attribution=ok，
  其中混合主题形态（一家规范化保住 Subject、另一家主题沉没）靠标记感知
  恢复抓取（attribution=ok-recovered）——按主题抓取在这些 case 上永远
  命中 postfix 副本，是本手术路线的已知仪器坑，已在 funnel.py 里防住。
- 签名臂/消费臂走 auth-postfix：capture@lab.test 经 transport_maps 进
  mailpit，bob@lab.test 不受影响（virtual_transport→Dovecot LMTP，
  39/40 投递成功）。
