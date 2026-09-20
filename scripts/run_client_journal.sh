#!/bin/bash
IP=${1:?server_ip required}; PORT=${2:-8080}; RUNS=${3:-1000}; WARM=${4:-100}; OUT=${5:-results/journal/vmware/client}
CORE=${CORE:-1}; BIN=${BIN:-./apake_bench_journal}
mkdir -p "$OUT"
TS=$(date +%Y%m%d_%H%M%S)
echo "[CLIENT] bin=$BIN $IP:$PORT runs=$RUNS warmup=$WARM core=$CORE -> $OUT/run_$TS.csv"
taskset -c "$CORE" "$BIN" client "$IP" "$PORT" "$RUNS" "$WARM" \
  > "$OUT/run_$TS.csv" 2> "$OUT/log_$TS.txt"
