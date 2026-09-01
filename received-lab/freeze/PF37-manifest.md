# PF37 环境冻结清单(freeze manifest)

- 冻结时间:2026-09-01
- 冻结 git commit:`2bcaac3`(freeze: pin base images by digest)
- 分支:`research/received-trace`
- 环境:WSL2 + Docker Desktop,compose 项目 `received-lab`,网络 `mailnet`

## 运行时事实(本次全部实验的依据)

| 项 | 值 |
| --- | --- |
| Postfix 版本 | **3.7.11**(Debian bookworm,`postconf mail_version`,见 `PF37-mail_version.txt`) |
| Postfix 生效配置 | `PF37-postconf-n.txt`(26 项,含 hopcount_limit=50、relayhost 链) |
| Postfix 编译默认值 | `PF37-postconf-d.txt`(1043 项) |
| PF37 镜像 ID | `sha256:860f16d93f527837b9a4003480ca653eef0276018bf9fff641b14cc9fb463697`(`received-lab-postfix1`) |
| Mailpit 版本 | **v1.31.0**,镜像 `axllent/mailpit@sha256:c96991d9bef73594c246d89ca81411d4e916f03e76a7d2d72fa2ab5dd3c9ce24` |
| 拓扑 | client → postfix1 → postfix2 → postfix3 → mailpit(hopcount_limit=50,TLS off,mydestination 空) |
| compose 解析结果 | `compose-config.resolved.yml` |

## 基础镜像 digest(已写入 Dockerfile / compose)

| 镜像 | digest |
| --- | --- |
| `debian:bookworm-slim`(postfix/Dockerfile) | `sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171` |
| `debian:sid`(postfix-current/Dockerfile,PF_CURRENT) | `sha256:c1acdb109bacb5adf0f2078892ac177ee2e2ce6f88e96c5b743998b5489d36a9` |
| `axllent/mailpit`(docker-compose.yml,替代 `:latest`) | `sha256:c96991d9bef73594c246d89ca81411d4e916f03e76a7d2d72fa2ab5dd3c9ce24`(= v1.31.0) |

## PF_CURRENT(PF11)运行时事实(Phase 3A,2026-09-01)

| 项 | 值 |
| --- | --- |
| Postfix 版本 | **3.11.6**(Debian sid,`postconf mail_version`) |
| 镜像 ID | `sha256:479b883ff0959ce26d5534c9a4c4bc485bc374e1116d17ec701374cd026e4b7a`(`received-lab-postfix1n`) |
| 基础镜像 | `debian:sid@sha256:c1acdb109bacb5adf0f2078892ac177ee2e2ce6f88e96c5b743998b5489d36a9` |
| 新增参数 | `non_empty_end_of_header_action`,**默认 `fix_quietly`**(3.7.11 无此参数) |
| 拓扑 | postfix1n → postfix2n → postfix3n → mailpit(hopcount_limit=50,与 PF37 一致) |
| 启动方式 | `docker compose --profile pf11 up -d --build`(默认 profile 不启动) |
| 实验后状态 | 策略覆盖已用 `postconf -X` 清除,`postconf -n` 无残留 |

## 已知注意事项

1. PF37 镜像最初构建于 2026-08-30,当时的 `debian:bookworm-slim` tag 指向的 digest 与上表(2026-09-01 拉取)可能不同;**冻结的运行时工件是镜像 ID `sha256:860f16d9...`**,只要不删除该镜像,行为即可复现。Dockerfile 中的 digest 约束的是未来的重建。
2. `postfix-current` 处于 compose `profiles: ["pf11"]`,默认 `docker compose up -d` 不构建不启动;启动方式:`docker compose --profile pf11 up -d --build`。
3. Debian sid 为滚动版,digest 已固定,但重建后软件版本以构建时 `postconf mail_version` 输出为准(Phase 3A 启动时会记录到 `results/phase3/`)。
4. Postfix 3.7 上游已于 2026-03-06 EOL(3.11.0 发布次日),这也是版本差分实验(Phase 3A)的背景事实。
