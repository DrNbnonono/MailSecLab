"""批量 parse 探针（python email compat32）：目录 -> 每文件一行 JSON。

与 parse.py（单样本，stdin）同口径，仅加 case 定位键与 field_count 维度，
供 gramfuzz stage-1 批量差分。比较元组 (received_count, from_in_headers,
field_count)，field_count 为去重字段名数（小写）。单文件异常不拖垮整批
——报错行与非报错行本身就是差分信号。
"""
import email
import json
import sys
from pathlib import Path

for p in sorted(Path(sys.argv[1]).glob("*.eml")):
    out = {"case": p.stem}
    try:
        msg = email.message_from_bytes(p.read_bytes())
        out.update({
            "received_count": len(msg.get_all("Received") or []),
            "from_in_headers": msg.get("From") is not None,
            "field_count": len({k.lower() for k, _ in msg.items()}),
            "defects": len(msg.defects),
        })
    except Exception as exc:  # 单文件故障记 error，继续后面的文件
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    print(json.dumps(out), flush=True)
