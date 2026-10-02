#!/bin/sh
batch() {
  start=$(date +%s)
  i=$1
  end=$(($1 + $2))
  while [ "$i" -lt "$end" ]; do
    printf 'From: Author <author@lab.test>\nSubject: perf %s\n\nbody %s\n' "$i" "$i" > /tmp/m.eml
    rspamc /tmp/m.eml >/dev/null
    i=$((i + 1))
  done
  echo $(( $(date +%s) - start ))
}
batch 0 100
batch 100 500
batch 600 500
batch 1100 500
