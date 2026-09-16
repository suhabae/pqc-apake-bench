#!/bin/bash
#
# 하나의 네트워크 조건에 대해 전체 실험을 수행한다.
#
# 순서:
# 환경 기록
# -> CPU performance 설정
# -> 네트워크 조건 적용
# -> tc 상태 기록
# -> ping 검증
# -> bandwidth 조건이면 iperf3 검증
# -> 30 trial
# -> 네트워크 조건 해제
#
# 서버를 먼저 실행하고 클라이언트를 실행한다.
#
# usage:
#
# Server:
# ./scripts/run_condition.sh \
#   server <client_ip> <label> <delay_ms> <rate_mbit>
#
# Client:
# ./scripts/run_condition.sh \
#   client <server_ip> <label> <delay_ms> <rate_mbit>
#

set -e

MODE=${1:?"server | client"}
PEER=${2:?"상대 머신 IP"}
LABEL=${3:?"조건 이름"}
DELAY=${4:-0}
RATE=${5:-0}

TRIALS=${6:-30}
PORT=${7:-8080}
RUNS=${8:-1000}
WARM=${9:-100}

IPERF_PORT=5201
IPERF_TIME=5

if [ "$MODE" != "server" ] && [ "$MODE" != "client" ]; then
    echo "[ERR] MODE는 server 또는 client 이어야 합니다."
    exit 1
fi

BASE="results/vmware/$LABEL"
OUT="$BASE/$MODE"

mkdir -p "$OUT"

cleanup() {
    echo
    echo "[*] 네트워크 조건 해제 중..."

    ./scripts/set_netem.sh "$PEER" clear \
        >/dev/null 2>&1 || true

    echo "[*] 네트워크 조건 해제 완료"
}

trap cleanup EXIT INT TERM

echo "================================================"
echo " condition = $LABEL"
echo " mode      = $MODE"
echo " delay     = ${DELAY} ms (one-way)"
echo " bandwidth = ${RATE} Mbps"
echo " trials    = $TRIALS"
echo " warmup    = $WARM"
echo " measured  = $RUNS"
echo "================================================"

# ------------------------------------------------
# 1. 실험 환경 기록
# ------------------------------------------------

./scripts/capture_env.sh "${LABEL}_${MODE}"

# ------------------------------------------------
# 2. CPU 설정
# ------------------------------------------------

./scripts/set_perf.sh

# ------------------------------------------------
# 3. 네트워크 조건 적용
# ------------------------------------------------

./scripts/set_netem.sh "$PEER" "$DELAY" "$RATE"

# ------------------------------------------------
# 4. 실제 qdisc 상태 저장
# ------------------------------------------------

echo "[*] tc qdisc 상태 저장"

./scripts/set_netem.sh "$PEER" show \
    | tee "$BASE/tc_${MODE}.txt"

# ------------------------------------------------
# 5. Client: 실제 RTT 검증
# ------------------------------------------------

if [ "$MODE" = "client" ]; then

    echo
    echo "[*] ping 100회 측정"

    ping -c 100 "$PEER" \
        | tee "$BASE/ping_${LABEL}.txt"

fi

# ------------------------------------------------
# 6. Bandwidth 조건이면 iperf3 검증
#
# Forward:
# Client -> Server
#
# Reverse:
# Server -> Client
# ------------------------------------------------

if [ "$RATE" != "0" ]; then

    if ! command -v iperf3 >/dev/null 2>&1; then
        echo "[ERR] iperf3가 설치되어 있지 않습니다."
        echo "sudo apt install -y iperf3"
        exit 1
    fi

    if [ "$MODE" = "server" ]; then

        echo
        echo "[*] iperf3 forward 검증 대기"

        iperf3 \
            -s \
            -1 \
            -p "$IPERF_PORT" \
            | tee "$BASE/iperf3_forward_server.txt"

        echo
        echo "[*] iperf3 reverse 검증 대기"

        iperf3 \
            -s \
            -1 \
            -p "$IPERF_PORT" \
            | tee "$BASE/iperf3_reverse_server.txt"

    else

        echo
        echo "[*] iperf3 Client -> Server"

        iperf3 \
            -c "$PEER" \
            -p "$IPERF_PORT" \
            -t "$IPERF_TIME" \
            | tee "$BASE/iperf3_forward_client.txt"

        sleep 1

        echo
        echo "[*] iperf3 Server -> Client"

        iperf3 \
            -c "$PEER" \
            -p "$IPERF_PORT" \
            -R \
            -t "$IPERF_TIME" \
            | tee "$BASE/iperf3_reverse_client.txt"

        # 서버가 iperf3 종료 후 aPAKE 서버를 띄울 시간을 확보
        sleep 2

    fi

fi

# ------------------------------------------------
# 7. aPAKE benchmark
# ------------------------------------------------

echo
echo "[*] PQC-aPAKE benchmark 시작"

if [ "$MODE" = "client" ]; then

    ./scripts/loop_client.sh \
        "$PEER" \
        "$TRIALS" \
        "$PORT" \
        "$RUNS" \
        "$WARM" \
        "$OUT"

else

    ./scripts/loop_server.sh \
        "$TRIALS" \
        "$PORT" \
        "$RUNS" \
        "$WARM" \
        "$OUT"

fi

echo
echo "[OK] $LABEL / $MODE 완료"
echo "[OK] result -> $OUT"