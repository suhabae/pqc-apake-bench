#!/bin/bash
T=${1:-30}; PORT=${2:-8080}; RUNS=${3:-1000}; WARM=${4:-100}; OUT=${5:-results/journal/vmware/server}
CORE=${CORE:-1}; BIN=${BIN:-./apake_bench_journal}
mkdir -p "$OUT"
for t in $(seq 1 "$T"); do
  echo "[SERVER] journal trial $t/$T"
  taskset -c "$CORE" "$BIN" server "$PORT" "$RUNS" "$WARM" \
    > "$OUT/trial_$(printf '%02d' "$t").csv" \
    2> "$OUT/trial_$(printf '%02d' "$t").log"
done
