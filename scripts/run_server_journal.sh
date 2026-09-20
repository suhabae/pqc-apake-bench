#!/bin/bash
PORT=${1:-8080}; RUNS=${2:-1000}; WARM=${3:-100}; OUT=${4:-results/journal/vmware/server}
CORE=${CORE:-1}; BIN=${BIN:-./apake_bench_journal}
mkdir -p "$OUT"
TS=$(date +%Y%m%d_%H%M%S)
echo "[SERVER] bin=$BIN port=$PORT runs=$RUNS warmup=$WARM core=$CORE -> $OUT/run_$TS.csv"
taskset -c "$CORE" "$BIN" server "$PORT" "$RUNS" "$WARM" \
  > "$OUT/run_$TS.csv" 2> "$OUT/log_$TS.txt"
