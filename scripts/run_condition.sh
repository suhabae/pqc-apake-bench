#!/bin/bash
# 한 가지 네트워크 조건에 대해 실험 한 세트를 끝까지 수행한다.
#   환경기록 -> CPU 고정 -> 조건 적용 -> (클라: ping 기록) -> 30 trial -> 조건 해제
#
# 저장소 루트에서 실행할 것. 서버를 먼저 띄우고, 그다음 클라이언트를 실행한다.
#
# usage:
#   [서버]   ./scripts/run_condition.sh server <client_ip> <label> <delay_ms> <rate_mbit> [trials] [port] [runs] [warmup]
#   [클라]   ./scripts/run_condition.sh client <server_ip> <label> <delay_ms> <rate_mbit> [trials] [port] [runs] [warmup]
#
# 예) RTT 10ms 조건 (one-way 5ms 를 양쪽에)
#   서버: ./scripts/run_condition.sh server 192.168.237.129 rtt_10ms 5 0
#   클라: ./scripts/run_condition.sh client 192.168.237.128 rtt_10ms 5 0
#
# 예) 대역폭 10Mbps 조건 (지연은 건드리지 않음)
#   서버: ./scripts/run_condition.sh server 192.168.237.129 bw_10mbps 0 10
#   클라: ./scripts/run_condition.sh client 192.168.237.128 bw_10mbps 0 10
set -e

MODE=${1:?"server | client"}
PEER=${2:?"상대 머신 IP"}
LABEL=${3:?"조건 이름 (baseline, rtt_10ms, bw_10mbps ...)"}
DELAY=${4:-0}
RATE=${5:-0}
TRIALS=${6:-30}
PORT=${7:-8080}
RUNS=${8:-1000}
WARM=${9:-100}

BASE="results/vmware/$LABEL"
OUT="$BASE/$MODE"
mkdir -p "$OUT"

# 실험이 중간에 실패하거나 Ctrl-C 로 멈춰도 네트워크 조건은 반드시 해제한다.
# (조건이 남아 있으면 다음 실험이 통째로 오염된다)
cleanup() {
  echo
  echo "[*] 네트워크 조건 해제 중..."
  ./scripts/set_netem.sh "$PEER" clear >/dev/null 2>&1 || true
  echo "[*] 해제 완료"
}
trap cleanup EXIT

echo "==============================================="
echo " 조건: $LABEL   ($MODE)"
echo " delay(one-way)=${DELAY}ms  rate=${RATE}mbit"
echo " trials=$TRIALS  warmup=$WARM  measured=$RUNS"
echo "==============================================="

# 1) 실험 환경 기록
./scripts/capture_env.sh "${LABEL}_${MODE}"

# 2) CPU 성능 고정
./scripts/set_perf.sh

# 3) 네트워크 조건 적용
./scripts/set_netem.sh "$PEER" "$DELAY" "$RATE"

# 4) 실행
if [ "$MODE" = "client" ]; then
  echo "[*] 조건 검증용 ping 100회 -> $BASE/ping_${LABEL}.txt"
  ping -c 100 "$PEER" | tee "$BASE/ping_${LABEL}.txt" | tail -3
  ./scripts/loop_client.sh "$PEER" "$TRIALS" "$PORT" "$RUNS" "$WARM" "$OUT"
else
  ./scripts/loop_server.sh "$TRIALS" "$PORT" "$RUNS" "$WARM" "$OUT"
fi

# 5) 조건 해제는 위의 trap 이 자동으로 처리한다.
echo "[OK] $LABEL / $MODE 완료 -> $OUT"
