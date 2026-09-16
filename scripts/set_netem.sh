#!/bin/bash
# 네트워크 조건(지연/대역폭)을 걸거나 해제한다.
# 서버·클라이언트 '양쪽 머신에서 각각' 실행해야 양방향 모두 조건이 걸린다.
#
# usage:
#   set_netem.sh <peer_ip> <delay_ms> <rate_mbit>   조건 적용 (0 = 제한 없음)
#   set_netem.sh <peer_ip> clear                    조건 해제
#   set_netem.sh <peer_ip> show                     현재 상태 확인
#
# 예:
#   set_netem.sh 192.168.237.128 0  0      # baseline (조건 없음)
#   set_netem.sh 192.168.237.128 5  0      # 양쪽에서 실행 -> RTT 약 +10ms
#   set_netem.sh 192.168.237.128 15 0      # 양쪽에서 실행 -> RTT 약 +30ms
#   set_netem.sh 192.168.237.128 0  10     # 대역폭 10Mbps, 지연은 그대로
#
# 주의: delay_ms 는 '한쪽 방향(one-way)' 지연이다.
#       RTT 목표값의 절반을 양쪽에 걸고, 반드시 ping 으로 실제 RTT 를 확인할 것.
set -e

PEER=${1:?peer_ip 필요}
ARG=${2:?"delay_ms | clear | show 필요"}
RATE=${3:-0}

# 상대 IP 로 나가는 네트워크 인터페이스 자동 탐지 (ens33, eth0 등)
IF=$(ip route get "$PEER" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
[ -n "$IF" ] || { echo "[ERR] $PEER 로 가는 인터페이스를 찾을 수 없음"; exit 1; }
echo "[*] interface = $IF  (peer = $PEER)"

case "$ARG" in
  show)
    tc qdisc show dev "$IF"
    exit 0
    ;;
  clear)
    sudo tc qdisc del dev "$IF" root 2>/dev/null || true
    echo "[OK] 조건 해제 (baseline 상태)"
    tc qdisc show dev "$IF"
    exit 0
    ;;
esac

DELAY=$ARG

# 항상 깨끗한 상태에서 다시 건다 (조건이 중첩되는 사고 방지)
sudo tc qdisc del dev "$IF" root 2>/dev/null || true

# 1) 지연: netem 을 root 로
if [ "$DELAY" != "0" ]; then
  sudo tc qdisc add dev "$IF" root handle 1: netem delay "${DELAY}ms"
  PARENT="parent 1:1"
else
  PARENT="root"
fi

# 2) 대역폭: tbf 를 netem 아래(또는 root)에
if [ "$RATE" != "0" ]; then
  # burst 는 rate/HZ 보다 커야 한다. 넉넉히 rate(mbit)*500 바이트 + 여유분.
  BURST=$(( RATE * 500 + 4000 ))
  # shellcheck disable=SC2086
  sudo tc qdisc add dev "$IF" $PARENT handle 10: tbf \
       rate "${RATE}mbit" burst "$BURST" latency 50ms
fi

echo "[OK] delay=${DELAY}ms(one-way)  rate=${RATE}mbit"
tc qdisc show dev "$IF"
echo
echo "[!] 조건이 의도대로 걸렸는지 ping 으로 반드시 확인하십시오:"
echo "    ping -c 20 $PEER"
