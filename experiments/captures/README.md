# 合成逐跳快照

这些文件模拟观测变化，未经过真实 MTA，也不提供传输结果。按 01 → 02 → 03 导入研究对比页，最后一个采集点可标记缺口。

- 01：一条 Received、两个相同 X-Duplicate、非 UTF-8 字段字节及无冒号畸形候选。
- 02：顶端新增一条 Received、Subject 标准折行、重复字段增加一份。
- 03：Subject 值改变，用于验证相邻区间选择和采集缺口提示。

CLI 与网页使用相同的比较及归档实现：

```powershell
.\.venv\Scripts\mailtrace-lab.exe diff .\experiments\captures\01-before.eml .\experiments\captures\02-after.eml .\experiments\captures\03-gap.eml
```

重复字段的候选对应保持不确定。摘要中的新增数量包括确定的 Received 新增与重复组的数量增加，但不会指定具体重复实例。文件必须作为字节读取；普通 UTF-8 编辑器可能替换 `X-Binary` 中的 `FF 80`，请使用原始文件上传或 ZIP 中的 `.eml`。
