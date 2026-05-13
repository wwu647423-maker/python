"""
modules/range_sum  —  Range Aggregation Payload
原始任务：计算 1..100 累加和
伪装定位：'对目标 IP 段做端口聚合分析'
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cyberkit import (
    C,
    banner,
    boot_sequence,
    fake_scan,
    hex_dump_line,
    log,
    section,
    success,
    type_out,
)


def aggregate_range(lo: int, hi: int) -> int:
    """对 [lo, hi] 闭区间执行累加运算。"""
    log("info", f"acquiring lock on integer range [{lo}, {hi}]")
    fake_scan("indexing target subnet", steps=16, delay=0.02)

    a = lo
    total = 0
    while a <= hi:
        total += a
        a += 1
        if a % 25 == 0:
            log("dbg", f"checkpoint  a={a:>3}  partial_sum={total}")
            time.sleep(0.05)

    success(f"aggregation complete — yield = {total}")
    return total


def main() -> None:
    banner("range_sum", "integer-range aggregation v0.1")
    boot_sequence([
        "loading arithmetic kernel",
        "calibrating overflow detector",
        "negotiating with /dev/urandom",
    ])

    section("RANGE AGGREGATION PAYLOAD")
    type_out("[*] target window = 1..100", color=C.CYAN)
    type_out("[*] strategy      = sequential additive sweep", color=C.CYAN)

    result = aggregate_range(1, 100)

    section("REPORT")
    print(hex_dump_line(result))
    print()
    print(f"  {C.BOLD}{C.GREEN}1-100数字和为：{result}{C.RESET}")
    print()
    log("ok", "session closed cleanly. exfil-channel terminated.")


if __name__ == "__main__":
    main()
