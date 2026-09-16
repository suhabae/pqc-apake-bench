#!/bin/bash
# 네트워크 조건(지연/대역폭)을 적용하거나 해제한다.
#
# 서버와 클라이언트 양쪽에서 각각 실행한다.
#
# usage:
#   set_netem.sh <peer_ip> <delay_ms> <rate_mbit>
#   set_netem.sh <peer_ip> clear
#   set_netem.sh <peer_ip> show
#
# 예:
#   set_netem.sh 192.168.237.128 0 0
#   set_netem.sh 192.168.237.128 5 0
#   set_netem.sh 192.168.237.128 0 10
#
# delay_ms는 한쪽 방향(one-way) 추가 지연이다.
# RTT +10 ms를 만들려면 양쪽 VM에 각각 5 ms를 적용한다.

set -e

PEER=${1:?peer_ip 필요}
ARG=${2:?"delay_ms | clear | show 필요"}
RATE=${3:-0}

# 상대 IP로 나가는 실제 네트워크 인터페이스 탐색
IF=$(ip route get "$PEER" | awk '{
    for(i=1;i<=NF;i++) {
        if($i=="dev") {
            print $(i+1)
            exit
        }
    }
}')

[ -n "$IF" ] || {
    echo "[ERR] $PEER 로 가는 인터페이스를 찾을 수 없음"
    exit 1
}

echo "[*] interface = $IF (peer = $PEER)"

case "$ARG" in
    show)
        tc -s qdisc show dev "$IF"
        exit 0
        ;;

    clear)
        sudo tc qdisc del dev "$IF" root 2>/dev/null || true
        echo "[OK] 네트워크 조건 해제"
        tc -s qdisc show dev "$IF"
        exit 0
        ;;
esac

DELAY=$ARG

# 이전 실험 조건 제거
sudo tc qdisc del dev "$IF" root 2>/dev/null || true

# baseline
if [ "$DELAY" = "0" ] && [ "$RATE" = "0" ]; then
    echo "[OK] baseline: 추가 delay/rate 제한 없음"
    tc -s qdisc show dev "$IF"
    exit 0
fi

NETEM_ARGS=()

# one-way delay
if [ "$DELAY" != "0" ]; then
    NETEM_ARGS+=(delay "${DELAY}ms")
fi

# bandwidth
if [ "$RATE" != "0" ]; then
    NETEM_ARGS+=(rate "${RATE}mbit")
fi

sudo tc qdisc add dev "$IF" root handle 1: netem "${NETEM_ARGS[@]}"

echo "[OK] delay=${DELAY}ms(one-way), rate=${RATE}mbit"
echo
tc -s qdisc show dev "$IF"