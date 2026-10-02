# 重放包

未提交，未外发。工作目录是 WSL `/mnt/e/MailSecLab/received-lab`，运行编号 `w1-20261001a`。

| 对象 | 路径 | 重放 |
| --- | --- | --- |
| 固定签名、From 插在前面 | `results/research/w1-20261001a/causal/cases/from-relaxed-n1-h1-insert-before/mutant.eml` | 四家验证器读这个文件 |
| 三跳后的同一对象 | `results/research/w1-20261001a/e2e/mutate-only/` | `research/lib/e2e.py` 已保存 SMTP 与验签 |
| Roundcube / SnappyMail | `results/research/w1-20261001a/clients/` | IMAP `bob`，截图与 `RECORD.md` |
| OpenDKIM / OpenDMARC | `results/research/w1-20261001a/clients/chain-b/legit.stored.eml` 与 `from-insert-before.stored.eml` | 当时 milter 为 `inet:msl-opendkim:8891, inet:msl-opendmarc:8893` |
| 最小化样本 | `results/research/w1-20261001a/fuzz/minimized/report.json` | `python3 research/lib/minimize.py` |
| Exim 4.92 | `results/research/w1-20261001a/exim492/` | 只含现有 I1 的 CRLF 与 LF 各一次 |
| 一万封防御 | `results/research/w1-20261001a/report/defense-10k.json` | 开发集与保留集已分开 |

披露草稿 `DISCLOSURE_DRAFT.md` 的 `disclosure_sent` 仍为 false。
