#!/bin/bash
# F-series: downstream impact of the byte channel (F1), hidden channel end-to-end
# (F2), limit configuration sensitivity (F3), DSN amplification grid (F4).
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/f-series
mkdir -p $OUT/f1 $OUT/logs
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
note() { echo "$*" | tee -a $REC; }

send() { local s=$1 p=$2 c=$3; shift 3
    local out; out=$($MC /scripts/send_received.py --server "$s" --port "$p" --case-id "$c" "$@" 2>/dev/null)
    echo "$(echo "$out" | grep -oP 'DATA_REPLY: \K.*' | tail -1)|$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+' | tail -1)"; }
check() { local c=$1
    $MC /scripts/check_delivery.py --case-id "$c" --timeout 8 2>/dev/null |
      grep -E "DELIVERED|BOUNCE" | tr '\n' ' '; }
msecs() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

cat > $REC <<'HDR'
# F 系列实验记录（2026-09-05）

目的：按价值排序验证 E 系列遗留问题 —— F1 字节通道下游成本；F2 隐藏通道端到端；
F3 上限的配置敏感性；F4 DSN 放大网格。环境同 E 系列（见 phase3/env.json），
新增 rspamd 3.4 容器（Debian bookworm，rbl/surbl/spf/dmarc/replies/url_redirector/
attachments 的 DNS 依赖检查已禁用 —— 离线实验无真实 DNS）。

HDR

############################################
log "== F1: byte-channel downstream cost (parsers + rspamd) =="
$MC /scripts/gen_f1_corpus.py /results/f-series/f1
cp results/phase3/corpus/V007.eml $OUT/f1/ 2>/dev/null
cp results/e-series/e3raw/E3-OSMTPD-received_sp.eml $OUT/f1/ 2>/dev/null
ls -la $OUT/f1/ > $OUT/logs/f1_files.txt 2>&1

CSV=$OUT/f1_downstream.csv
echo "file,bytes,py_ms,py_rc,node_ms,node_rc,go_ms,go_rc,rspamd_ms,rspamd_score_action,rspamd_symbols" > $CSV
for f in $OUT/f1/*.eml; do
    b=$(basename $f .eml); sz=$(stat -c%s "$f"); cf="/results/f-series/f1/$b.eml"
    # parser timings (wall clock incl. docker exec overhead ~40-80ms)
    t0=$(date +%s%N)
    pj=$($MC /scripts/parse_python.py "$cf" 2>/dev/null)
    pym=$(msecs $t0); prc=$(echo "$pj" | grep -oP '"received_count":\s*\K\d+'); perr=$(echo "$pj" | grep -oP '"parse_error":\s*\K[^,]*')
    t0=$(date +%s%N)
    nj=$(docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "$cf" 2>/dev/null)
    nom=$(msecs $t0); nrc=$(echo "$nj" | grep -oP '"received_count":\K\d+')
    t0=$(date +%s%N)
    gj=$(docker exec parser-go /usr/local/bin/parse_go "$cf" 2>/dev/null)
    gom=$(msecs $t0); grc=$(echo "$gj" | grep -oP '"received_count":\K\d+')
    # rspamd scan
    t0=$(date +%s%N)
    rj=$(docker exec rspamd rspamc --json "$cf" 2>/dev/null)
    rsm=$(msecs $t0)
    echo "$rj" > $OUT/logs/rspamd_$b.json
    score=$(echo "$rj" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('score','?'), '|', d.get('action','?'))
except Exception as e: print('PARSE_ERR')")
    syms=$(echo "$rj" | python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
    s=d.get('symbols',{})
    print(';'.join(list(s)[:12]))
except Exception: print('')")
    echo "$b,$sz,$pym,${prc:-ERR(${perr:0:30})},$nom,${nrc:-ERR},$gom,${grc:-ERR},$rsm,$score,$syms" >> $CSV
    echo "  $b ($sz B): py=${pym}ms rc=$prc | node=${nom}ms rc=$nrc | go=${gom}ms rc=$grc | rspamd=${rsm}ms $score"
done
log "F1 done -> f1_downstream.csv (注意: parser 计时含 docker exec ~50-80ms 开销)"

############################################
log "== F2: hidden channel end-to-end (OSMTPD -> PF/Exim -> mailpit) =="
docker exec postfix1 postconf -e 'relayhost = [mailpit]:1025'; docker exec postfix1 postfix reload >/dev/null
docker exec opensmtpd sh -c "sed -i 's|smtp://mailpit:1025|smtp://postfix1:25|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker restart opensmtpd >/dev/null; sleep 3

CSV=$OUT/f2_hidden.csv
echo "path,N,osmtpd_code,final_delivered,exact,wsp,ci,node_received,notes" > $CSV
run_f2() { # target_name N
    local tgt=$1
    local n=$2
    local c="F2-$tgt-N$n"
    local res; res=$(send opensmtpd 25 $c -n $n --header-name "Received ")
    local code=${res%%|*}
    local d="-" ex="-" wsp="-" ci="-" nrc="-"
    if echo "$code" | grep -q '^2'; then
        read -r _ d _ <<< "$(check $c)"
        if echo "$d" | grep -q yes; then
            $MC /scripts/check_delivery.py --dump-case "$c" > "$OUT/logs/$c.eml" 2>/dev/null
            local cnts; cnts=$($MC /scripts/count_received.py "/results/f-series/logs/$c.eml" 2>/dev/null)
            ex=$(echo "$cnts" | grep -oP '"received_exact":\K\d+')
            wsp=$(echo "$cnts" | grep -oP '"received_wsp":\K\d+')
            ci=$(echo "$cnts" | grep -oP '"received_ci":\K\d+')
            nrc=$(docker exec -e NODE_PATH=/app/node_modules parser-node node /scripts/parse_node.js "/results/f-series/logs/$c.eml" 2>/dev/null | grep -oP '"received_count":\K\d+')
        fi
    fi
    echo "$tgt,$n,$code,$d,$ex,$wsp,$ci,${nrc:--}," >> $CSV
    echo "  F2 $tgt N=$n code=$code delivered=$d exact=$ex wsp=$wsp ci=$ci node=$nrc"
}
run_f2 PF 40
run_f2 PF 100
docker exec exim sh -c "sed -i 's|route_list = \* mailpit byname|route_list = * postfix1 byname|; s|port = 1025|port = 25|' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 3
run_f2 EX 25
run_f2 EX 100
log "F2 done; restoring osmtpd/exim -> mailpit"
docker exec opensmtpd sh -c "sed -i 's|smtp://postfix1:25|smtp://mailpit:1025|' /etc/smtpd.conf /etc/mail/smtpd.conf"
docker exec exim sh -c "sed -i 's|route_list = \* postfix1 byname|route_list = * mailpit byname|; s|port = 25|port = 1025|' /etc/exim/exim.conf"
docker restart opensmtpd exim >/dev/null

############################################
log "== F3: limit configuration sensitivity =="
CSV=$OUT/f3_sensitivity.csv
echo "knob,value,target,N,smtp_code,delivered,notes" > $CSV

docker exec postfix1 postconf -e 'hopcount_limit = 100'; docker exec postfix1 postfix reload >/dev/null; sleep 1
for n in 98 99 100 101 102; do
    c="F3-PF-H100-N$n"; r=$(send postfix1 25 $c -n $n); code=${r%%|*}
    d=$(check $c)
    echo "hopcount_limit,100,postfix1,$n,$code,$d," >> $CSV
    echo "  PF hopcount=100 N=$n -> $code $d"
done
docker exec postfix1 postconf -e 'hopcount_limit = 50'; docker exec postfix1 postfix reload >/dev/null

docker exec exim sh -c "sed -i 's|^primary_hostname = exim.lab.test|primary_hostname = exim.lab.test\nreceived_headers_max = 60|' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 3
for n in 29 58 59 60 61 62; do
    c="F3-EX-RH60-N$n"; r=$(send exim 25 $c -n $n); code=${r%%|*}
    d=$(check $c)
    echo "received_headers_max,60,exim,$n,$code,$d," >> $CSV
    echo "  EX rhmax=60 N=$n -> $code $d"
done
docker exec exim sh -c "sed -i '/^received_headers_max = 60/d; s|^primary_hostname = exim.lab.test|primary_hostname = exim.lab.test\nheader_maxsize = 4194304|' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 3
for n in 40 45 50; do
    c="F3-EX-HM4M-F$n"; r=$(send exim 25 $c --style folded -n $n --fold-kb 90); code=${r%%|*}
    d=$(check $c)
    echo "header_maxsize,4M,exim,fold$n,$code,$d," >> $CSV
    echo "  EX hmmax=4M folded N=$n -> $code $d"
done
docker exec exim sh -c "sed -i '/^header_maxsize = 4194304/d' /etc/exim/exim.conf"
docker restart exim >/dev/null; sleep 2
log "F3 done（postfix1 恢复 hopcount=50；exim 两参数已还原）"

############################################
log "== F4: DSN amplification grid (loop limit=8, hopcount-blind big bodies) =="
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix1 postconf -e 'hopcount_limit = 8'
docker exec postfix2 postconf -e 'hopcount_limit = 8'
docker exec postfix3 postconf -e 'hopcount_limit = 8'
docker exec postfix3 postconf -e 'relayhost = [postfix1]:25'
for h in postfix1 postfix2 postfix3; do docker exec $h postfix reload >/dev/null; done
sleep 2
CSV=$OUT/f4_amplify.csv
echo "xreceived_n,message_bytes,cycles_seen,last_cycle_size,dsn_size,ratio_dsn_over_orig,notes" > $CSV
for n in 0 1 5 20; do
    c="F4-XF$n"
    before=$(docker logs postfix1 2>&1 | wc -l)
    out=$($MC /scripts/send_folded_xreceived.py $n $c postfix1 2>&1)
    code=$(echo "$out" | grep -oP 'DATA_REPLY: \K.*' | tail -1)
    bytes=$(echo "$out" | grep -oP 'MESSAGE_BYTES: \K\d+' | tail -1)
    sleep 40
    docker logs postfix1 2>&1 | tail -n +$((before+1)) > $OUT/logs/f4_$n.log
    sizes=$(grep "from=<alice@sender.lab.test>" $OUT/logs/f4_$n.log | grep -oP 'size=\K\d+' | paste -sd';' -)
    last=$(echo "$sizes" | awk -F';' '{print $NF}')
    dsn=$(grep 'from=<>' $OUT/logs/f4_$n.log | grep -oP 'size=\K\d+' | tail -1)
    ratio=$(python3 -c "print(f'{$dsn/$bytes:.3f}' if $dsn and $bytes else '')" 2>/dev/null)
    cyc=$(echo "$sizes" | awk -F';' '{print NF}')
    echo "$n,$bytes,$cyc,$last,$dsn,$ratio," >> $CSV
    echo "  F4 n=$n bytes=$bytes cycles=$cyc sizes=$sizes dsn=$dsn ratio=${ratio:-NA}"
done
log "F4 done; restoring chain"
docker exec postfix1 postconf -e 'relayhost = [postfix2]:25'
docker exec postfix2 postconf -e 'relayhost = [postfix3]:25'
docker exec postfix3 postconf -e 'relayhost = [mailpit]:1025'
for h in postfix1 postfix2 postfix3; do docker exec $h postconf -e 'hopcount_limit = 50'; docker exec $h postfix reload >/dev/null; done
log "== F-SERIES ALL DONE =="
