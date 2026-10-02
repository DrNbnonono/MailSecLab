# 第 4 周最小化

每类状态按出现次数取最多 10 个已保存样本，重新验证，再撤掉那一次改动再验证。签名字节与语料父本一致。结果在 `report.json`。

四类：

- `dkimpy=parse-error`，perl/go/rspamd `pass`：10 个里 8 个重新出现同一分歧，撤掉一次插入或一个字节后分歧消失。
- `dkimpy=fail`，perl/go `pass`，rspamd `fail`：3 个都重新出现，且都是一次插入。其中 `split-a5fdca034956.eml` 是在签名后插入 `From: Added <added@evil.test>`，与第 2 周 From 插在前面的对象相同。
- 四家都失败或 `parse-error`：10 个里 7 个是一个字节的改动，撤掉后不再是这个状态。
- 有一条 perl `timeout` 的记录没有复现，不计。

没有出现第 2 周矩阵以外的状态组合。
