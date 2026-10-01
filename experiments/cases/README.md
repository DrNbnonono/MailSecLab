# 合成研究用例

这些参数只使用保留的 `.example` 域名和固定时间，不引用真实邮件。生成结果自动存入实验目录。

```powershell
.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\received-baseline.json --sweep .\experiments\cases\received-counts.json
.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\received-baseline.json --sweep .\experiments\cases\line-boundaries.json
.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\received-baseline.json --sweep .\experiments\cases\header-sizes.json
.\.venv\Scripts\mailtrace-lab.exe forge .\experiments\cases\ambiguity.json
```

`received-counts.json` 覆盖 0/50/51/200 条边界；`line-boundaries.json` 覆盖 997/998/999 字节物理行；`header-sizes.json` 精确控制头区字节数。三个扫描文件分别只覆盖指定轴。

`ambiguity.json` 保留字段列表顺序、重复实例和冒号前空格。候选 Received 与语义识别数量可能不同，这是实验现象，不是传输结果。将 `pre_colon_space` 改为 false，可单独研究有效语法下的回返路径与无效日期。

逐跳对比的 `.eml` 必须按真实采集顺序传入；生成样本组不会自动转为传输链。本轮不执行 SMTP，不测量 MTA 接受或拒绝。
