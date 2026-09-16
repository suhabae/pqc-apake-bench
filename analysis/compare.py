#!/usr/bin/env python3
"""
compare.py — 여러 네트워크 조건의 결과를 한 표로 비교한다.

analyze.py 는 한 조건을 자세히 보는 도구이고,
compare.py 는 여러 조건을 나란히 놓고 비교하는 도구다.

사용법:
    python3 analysis/compare.py \
        baseline=results/vmware/baseline \
        rtt_10ms=results/vmware/rtt_10ms \
        rtt_30ms=results/vmware/rtt_30ms \
        rtt_50ms=results/vmware/rtt_50ms \
        --plot analysis/figures/latency_compare.png

각 폴더는 client/ 와 server/ 하위 폴더를 가진다고 가정한다.
출력 단위는 ms.
"""
import sys, os, glob, argparse, statistics as st

def load(dirpath, ncols):
    """폴더 안의 모든 CSV 를 읽는다. 상태 메시지/헤더 줄은 무시."""
    rows = []
    for path in sorted(glob.glob(os.path.join(dirpath, "*.csv"))):
        with open(path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line[0].isdigit():
                    continue
                p = line.split(",")
                if len(p) != ncols:
                    continue
                try:
                    rows.append([int(x) for x in p])
                except ValueError:
                    continue
    return rows

def stats(vals):
    """ns 리스트 -> ms 단위 통계"""
    if not vals:
        return None
    v = sorted(vals)
    n = len(v)
    ms = lambda x: x / 1e6
    pct = lambda p: v[min(n - 1, int(p * n))]
    return {"n": n, "mean": ms(st.mean(v)), "median": ms(st.median(v)),
            "p95": ms(pct(0.95)), "p99": ms(pct(0.99)), "max": ms(v[-1])}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("conditions", nargs="+", help="라벨=폴더경로")
    ap.add_argument("--plot", default=None, help="비교 그래프 저장 경로(png)")
    args = ap.parse_args()

    table = []
    for item in args.conditions:
        if "=" not in item:
            sys.exit(f"형식 오류: {item}  (라벨=폴더경로 형태로 주십시오)")
        label, d = item.split("=", 1)
        cli = load(os.path.join(d, "client"), 5)
        srv = load(os.path.join(d, "server"), 2)
        if not cli:
            print(f"[!] {label}: client CSV 를 찾을 수 없음 ({d}/client)")
            continue
        table.append({
            "label":  label,
            "n":      len(cli),
            "total":  stats([r[4] for r in cli]),
            "net":    stats([r[2] for r in cli]),
            "round1": stats([r[1] for r in cli]),
            "finish": stats([r[3] for r in cli]),
            "srv":    stats([r[1] for r in srv]) if srv else None,
        })

    if not table:
        sys.exit("비교할 데이터가 없습니다.")

    # ---- 표 출력 (단위: ms) ----
    line = "-" * 104
    print(line)
    print(f"{'condition':<14}{'n':>7}{'total_med':>11}{'total_mean':>12}"
          f"{'total_p95':>11}{'total_p99':>11}{'net_med':>10}"
          f"{'round1':>9}{'finish':>9}{'srv_r2':>9}")
    print(line)
    for r in table:
        srv = f"{r['srv']['mean']:.3f}" if r["srv"] else "-"
        print(f"{r['label']:<14}{r['n']:>7}{r['total']['median']:>11.3f}"
              f"{r['total']['mean']:>12.3f}{r['total']['p95']:>11.3f}"
              f"{r['total']['p99']:>11.3f}{r['net']['median']:>10.3f}"
              f"{r['round1']['mean']:>9.3f}{r['finish']['mean']:>9.3f}{srv:>9}")
    print(line)
    print("단위: ms   (round1/finish/srv_r2 는 평균, total_med/net_med 는 중앙값)")

    # ---- baseline 대비 증가량 ----
    base = table[0]
    if len(table) > 1:
        print(f"\n[{base['label']}] 대비 total_login 중앙값 변화")
        for r in table[1:]:
            d = r["total"]["median"] - base["total"]["median"]
            x = r["total"]["median"] / base["total"]["median"]
            print(f"  {r['label']:<14} {d:+8.3f} ms   (x{x:.2f})")

    # ---- 그래프 ----
    if args.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        os.makedirs(os.path.dirname(args.plot) or ".", exist_ok=True)
        labels = [r["label"] for r in table]
        med = [r["total"]["median"] for r in table]
        p95 = [r["total"]["p95"] for r in table]
        x = range(len(labels)); w = 0.38
        plt.figure(figsize=(8, 4.5))
        plt.bar([i - w / 2 for i in x], med, w, label="median")
        plt.bar([i + w / 2 for i in x], p95, w, label="p95")
        plt.xticks(list(x), labels, rotation=15)
        plt.ylabel("total_login (ms)")
        plt.title("Total login latency by network condition")
        plt.legend(); plt.grid(True, axis="y", alpha=0.3); plt.tight_layout()
        plt.savefig(args.plot, dpi=150); plt.close()
        print(f"\n[OK] 그래프 저장 -> {args.plot}")

if __name__ == "__main__":
    main()
