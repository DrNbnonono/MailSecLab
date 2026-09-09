#!/bin/bash
# K1: DKIM verifier differential matrix.
# Verifiers: dkimpy (client), opendkim-testmsg (opendkim), dkim-verify (go-msgauth).
# DNS: dnsmasq at 172.31.0.53 serving j1._domainkey.lab.test TXT.
set -u
cd /mnt/e/MailSecLab/received-lab
OUT=results/k-series
mkdir -p $OUT
MC="docker exec mail-client python3"
REC=$OUT/RECORD.md
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a $REC; }
( while :; do docker info >/dev/null 2>&1; sleep 4; done ) &
KEEPER=$!
trap "kill $KEEPER 2>/dev/null" EXIT
keepup() { docker compose --profile k1 --profile frspamd --profile pf11 up -d >/dev/null 2>&1; }

cat > $REC <<'HDR'
# K 系列实验记录（2026-09-07）

**问题**：同一个 DKIM 签名（同字节、同密钥 j1/lab.test/relaxed-relaxed），
在不同验证器眼里是否存在、是否有效？

**验证器**：
- dkimpy 1.1.8（Python，client 容器，dnsfunc 覆盖本地公钥）
- perl Mail::DKIM（CPAN，独立 Perl 实现，DNS → dnsmasq 172.31.0.53）；
  [opendkim-testmsg 在 bookworm 打包上对所有输入（含最小合法报文）报
  dkim_chunk(): Syntax error —— 已记录为发现，替换为 perl 实现]
- dkim-verify（go-msgauth v0.6.8，Go，DNS → dnsmasq）

**语料**（scripts/mk_kb_corpus.py 生成，结构自检通过；另复用 j 系列产物）：
KB1 干净对照 / KB2 签名后注入 Receíved 异常头 / KB3 重复 From+Subject /
KB4 正文后第二头块 / KB5 l= 签名 + 正文含头状行 / j1_stored（截断后）/
j2_appended（l= 追加）/ j3_stored（淹没后存储版）。

HDR
log "== PRE-UP =="
keepup; sleep 2
# regenerate pub record into mounted volume for dnsmasq
$MC /scripts/mk_kb_corpus.py /results/k-series
# re-sign KB bases with the SAME j1 key/selector (deterministic apart from t=)
for kb in KB1-clean KB2-base KB3-dupfrom KB4-secondblock; do
    $MC /scripts/dkim_sign.py /results/k-series/$kb.eml /results/k-series/$kb.signed.eml j1 lab.test false | tail -1 | tee -a $REC
done
$MC /scripts/dkim_sign.py /results/k-series/KB5-lplusheaders.eml /results/k-series/KB5-lplusheaders.signed.eml j1 lab.test true | tail -1 | tee -a $REC
# KB2: inject anomaly AFTER signing
$MC /scripts/j3_inject.py /results/k-series/KB2-base.signed.eml /results/k-series/KB2-anomaly.signed.eml | tee -a $REC
# restart dnsmasq to pick up pub record (it was built at container start)
docker restart dns >/dev/null; sleep 2

verify_dkimpy() { # file -> result
    $MC /scripts/dkim_verify.py "$1" 2>/dev/null | head -1
}
verify_opendkim() { # file -> result  (opendkim-testmsg broken on bookworm: replaced by perl Mail::DKIM)
    docker exec perl-mail-dkim sh -c "verify.pl < '$1'" 2>&1 | tail -1
}
verify_go() { # file -> result
    docker exec go-msgauth sh -c "dkim-verify < '$1'" 2>&1 | tail -1
}

log "== sanity: KB1-clean must pass on all three =="
for v in dkimpy opendkim go; do
    case $v in
      dkimpy) r=$(verify_dkimpy /results/k-series/KB1-clean.signed.eml);;
      opendkim) r=$(verify_opendkim /results/k-series/KB1-clean.signed.eml);;
      go) r=$(verify_go /results/k-series/KB1-clean.signed.eml);;
    esac
    echo "  KB1-clean @$v: $r" | tee -a $REC
done

log "== K1 matrix =="
echo "corpus,dkimpy,perl-mail-dkim,go-msgauth" > $OUT/k1_matrix.csv
declare -A FILES=(
  [KB1-clean]="/results/k-series/KB1-clean.signed.eml"
  [KB2-anomaly-injected]="/results/k-series/KB2-anomaly.signed.eml"
  [KB3-dup-from-subject]="/results/k-series/KB3-dupfrom.signed.eml"
  [KB4-second-header-block]="/results/k-series/KB4-secondblock.signed.eml"
  [KB5-l=+header-shaped-body]="/results/k-series/KB5-lplusheaders.signed.eml"
  [j1_stored-truncated]="/results/j-series/j1_stored.eml"
  [j2_appended-l=]="/results/j-series/j2_appended.eml"
  [j3_stored-drowned]="/results/j-series/j3_stored.eml"
)
for k in "KB1-clean" "KB2-anomaly-injected" "KB3-dup-from-subject" "KB4-second-header-block" "KB5-l=+header-shaped-body" "j1_stored-truncated" "j2_appended-l=" "j3_stored-drowned"; do
    f=${FILES[$k]}
    rd=$(verify_dkimpy "$f"); ro=$(verify_opendkim "$f"); rg=$(verify_go "$f")
    cl=$(echo "$rd" | sed 's/VERIFY: //' | tr '\n' ' ' | sed 's/  */ /g')
    co=$(echo "$ro" | tr -d '\r' | tr '\n' ' ')
    cg=$(echo "$rg" | sed 's/^2026[^ ]* [0-9:]* //' | tr -d '\r' | tr '\n' ' ')
    echo "$k,\"$cl\",\"$co\",\"$cg\"" >> $OUT/k1_matrix.csv
    echo "  $k | py=$cl | od=$co | go=$cg" | tee -a $REC
done
log "== K1 DONE (K2 rows included above: KB5, j2_appended) =="
