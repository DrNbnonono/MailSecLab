# 被动语料清单（MANIFEST，2026-10-03）

语料本体在 `received-lab/corpus/`（gitignore，不入库）；本清单与其 sha256 入库。
下载均在 Windows host 侧完成（setup 网络行为，与 RFC/PDF 下载同性质；实验不出公网发信）。

| 语料 | 来源 URL | sha256 | 大小 | 消息数 | 年代 |
| --- | --- | --- | --- | --- | --- |
| nazario/phishing3.mbox | https://monkey.org/~jose/phishing/phishing3.mbox | `b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841` | 20,067,215 B | 2,279 | 2004–2007 钓鱼 |
| enron-raw-ham/beck-s.tar.gz | https://www.aueb.gr/users/ion/data/enron-spam/raw/ham/beck-s.tar.gz | `28ad9e6b40a323fba13ece2e63a0aee6f66435ac3f1fd2974a6777eeb39456a2` | 1,203,077 B | 1,977 | 1999–2002 合法邮件（Enron beck-s） |

**已确认失效的源**（2026-10-03 核验，后续换镜像）：
- SpamAssassin public corpus（spamassassin.apache.org/old/publiccorpus/）→ 302/404，官方「cleaning house」下线。
- TREC 2007（plg.uwaterloo.ca/~gvcormac/treccorpus07/trec07p.tgz）→ 重定向链终止于 404。
- AUEB Enron-Spam 预处理文件名易错：实际在 `raw/` 与 `preprocessed/` 子目录下。

**待补源**（计划任务 6.1 全集）：lore.kernel.org / W3C / IETF 公共邮件档案（现代全头 raw mbox，现代性关键）；Nazario 其余年份；AUEB raw ham 其余用户。
