#!/bin/bash
IP=${1:?server_ip required}; T=${2:-30}; PORT=${3:-8080}; RUNS=${4:-1000}; WARM=${5:-100}; OUT=${6:-results/journal/vmware/client}
CORE=${CORE:-1}; BIN=${BIN:-./apake_bench_journal}
mkdir -p "$OUT"
for t in $(seq 1 "$T"); do
  echo "[CLIENT] journal trial $t/$T"
  taskset -c "$CORE" "$BIN" client "$IP" "$PORT" "$RUNS" "$WARM" \
    > "$OUT/trial_$(printf '%02d' "$t").csv" \
    2> "$OUT/trial_$(printf '%02d' "$t").log"
  sleep 1
done
