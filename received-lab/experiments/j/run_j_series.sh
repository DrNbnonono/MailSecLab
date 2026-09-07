#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/j-series
mkdir -p $OUT
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT

cat > $REC <<'HDR'
# J 系列实验记录（2026-09-06）

**问题**：传输层的静默头截断 / WSP 改写 / l= 前缀语义，与真实 DKIM 签名验证的交互。
**签名/验证**：dkimpy（client 容器内，构建期经代理 pip 安装）；验证时用本地公钥记录
覆盖 selector 查询（无需 DNS）。签名域 lab.test，selector j1，relaxed/relaxed。
**链路**：postfix1 → postfix2 → postfix3 → mailpit（标准链，hopcount=50）。

HDR
log "== PRE-UP & keygen =="
docker compose --profile frspamd --profile pf11 up -d 2>&1 | tail -1
sleep 2
docker exec postfix1 postconf -e 'hopcount_limit = 50'; docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'; docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3; do docker exec $h postconf -e 'hopcount_limit = 50'; docker exec $h postfix reload >/dev/null; done
docker exec mail-client sh -c 'cd /results/j-series 2>/dev/null || mkdir -p /results/j-series && cd /results/j-series; openssl genrsa -out dkim.key 2048 2>/dev/null' >/dev/null
[ -s $OUT/dkim.key ] && log "key generated ($(wc -c < $OUT/dkim.key) bytes)" || { log "keygen failed"; exit 1; }
docker exec mail-client sh -c "openssl rsa -in /results/j-series/dkim.key -pubout 2>/dev/null | grep -v '-' | tr -d '
' > /results/j-series/dkim.pub.txt" && log "pub record exported ($(wc -c < $OUT/dkim.pub.txt) bytes)"

log "== J1: oversized folded header (150KB) + DKIM h=x-gen => relay truncation =="
$MC /scripts/mk_j1_msg.py /results/j-series/j1_base.eml >/dev/null
$MC /scripts/dkim_sign.py /results/j-series/j1_base.eml /results/j-series/j1_signed.eml j1 lab.test false from,to,subject,message-id,x-gen | tee -a $REC
echo -n "pre-relay verify: " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j1_signed.eml | tee -a $REC
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/j-series/j1_signed.eml --case-id J1-relay 2>&1 | grep DATA_REPLY | tee -a $REC
sleep 3
$MC /scripts/check_delivery.py --dump-case J1-relay > $OUT/j1_stored.eml 2>/dev/null
echo "stored bytes: $(wc -c < $OUT/j1_stored.eml)" | tee -a $REC
echo -n "post-relay verify: " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j1_stored.eml | tee -a $REC

log "== J2: l= prefix signature + appended body content =="
cat > $OUT/j2_base.eml <<'EOF2'
X-Case-ID: J2-relay
From: Alice <alice@sender.lab.test>
To: Bob <bob@receiver.lab.test>
Subject: J2 l= test
Message-ID: <j2@sender.lab.test>

This is the benign signed body.
EOF2
unix2dos $OUT/j2_base.eml 2>/dev/null || sed -i 's/$/\r/' $OUT/j2_base.eml
$MC /scripts/dkim_sign.py /results/j-series/j2_base.eml /results/j-series/j2_signed.eml j1 lab.test true | tee -a $REC
echo -n "verify (clean): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j2_signed.eml | tee -a $REC
$MC /scripts/j2_append.py /results/j-series/j2_signed.eml /results/j-series/j2_appended.eml | tee -a $REC
echo -n "verify (appended spam, pre-relay): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j2_appended.eml | tee -a $REC
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/j-series/j2_appended.eml --case-id J2-relay 2>&1 | grep DATA_REPLY | tee -a $REC
sleep 3
$MC /scripts/check_delivery.py --dump-case J2-relay > $OUT/j2_stored.eml 2>/dev/null
echo -n "verify (appended spam, post-relay): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j2_stored.eml | tee -a $REC

log "== J3: signed message + post-signing anomaly injection =="
$MC /scripts/mk_j3_msg.py /results/j-series/j3_clean.eml clean >/dev/null
$MC /scripts/dkim_sign.py /results/j-series/j3_clean.eml /results/j-series/j3_signed.eml j1 lab.test false from,to,subject,message-id | tee -a $REC
echo -n "verify (clean, pre-injection): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_signed.eml | tee -a $REC
$MC /scripts/j3_inject.py /results/j-series/j3_signed.eml /results/j-series/j3_injected.eml | tee -a $REC
echo -n "verify (post-injection, pre-relay): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_injected.eml | tee -a $REC
$MC /scripts/send_received.py --server postfix1 --port 25 --input-file /results/j-series/j3_injected.eml --case-id J3-relay 2>&1 | grep DATA_REPLY | tee -a $REC
sleep 3
$MC /scripts/check_delivery.py --dump-case J3-relay > $OUT/j3_stored.eml 2>/dev/null
echo "stored bytes: $(wc -c < $OUT/j3_stored.eml); stored first line: $(head -c 60 $OUT/j3_stored.eml | tr '
' '|')" | tee -a $REC
echo -n "verify (post-relay, as stored): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_stored.eml | tee -a $REC
$MC /scripts/j3_repair.py /results/j-series/j3_stored.eml /results/j-series/j3_repaired.eml | tee -a $REC
echo -n "verify (repaired: anomaly line removed): " | tee -a $REC
$MC /scripts/dkim_verify.py /results/j-series/j3_repaired.eml | tee -a $REC
echo "-- parser view of STORED j3 (python):" | tee -a $REC
$MC /scripts/parse_python.py /results/j-series/j3_stored.eml 2>/dev/null | head -c 300 | tee -a $REC
echo "" | tee -a $REC
log "== J-SERIES DONE =="
