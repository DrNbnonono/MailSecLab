# experiments/ — 实验驱动脚本索引

宿主侧（Git Bash / WSL）运行的实验驱动脚本，按系列组织。
容器侧工具统一在 `../scripts/`（挂载到容器 `/scripts`）。

每个系列目录内：`run_*` 为该系列主驱动；其余为边界细化（refine）、问题修复迭代（v2/v3）。
所有脚本自带 pre-reset / keeper（对抗 Docker Desktop resource-saver 停 VM），
从任意目录运行均可（内部使用绝对路径 `cd /mnt/e/MailSecLab/received-lab`）。

| 系列 | 主驱动 | 说明 | 结果 |
| --- | --- | --- | --- |
| Phase 1–3 | `../scripts/{scan,phase2,phase3,phase3b,phase3c,loop_test}.sh` | hopcount/RFC 路径/版本·MTA·parser 差分 | `../results/{,phase3,phase3c}` |
| E | `e/run_e_series.sh`（+`e/refine_e.sh` 边界细化） | 数量/字节上限、盲区、异构链、放大 | `../results/e-series/` |
| F | `f/run_f_series.sh`（F2 重跑：`f/run_f2_only.sh`） | 字节通道下游成本（rspamd）、隐藏通道端到端、配置敏感性、放大网格 | `../results/f-series/` |
| G | `g/run_g_series.sh` → `g/run_g4_r3_v2.sh`（含 G1–G3 变体与修复迭代） | rspamd 丢头证伪（语料双 CRLF 纠错）、WSP 规范化归因、R3 重做 | `../results/g-series/` |
| H | `h/run_h_final.sh`（+`h/run_h_tail.sh`） | rspamd 信任边界 / source 认定 | `../results/h-series/` |
| I | `i/run_i1_v3.sh`（exim 对：`i/run_exim_v2.sh`；裸 LF 直连：`i/run_i_series.sh`） | SMTP 走私矩阵、链自洽伪造 | `../results/i-series/` |
| J | `j/run_j_series.sh`（+`j/run_j3_final.sh`） | DKIM × 截断/l=/淹没 | `../results/j-series/` |

宿主工具：`../tools/gen_report.py`（生成 `../results/report.html`）、
`../tools/pull_image.py`（daemon 无网环境下的 digest 校验离线拉镜像）。
