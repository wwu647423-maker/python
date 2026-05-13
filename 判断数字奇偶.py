"""
modules/parity_oracle  —  LSB Parity Oracle
原始任务：随机生成 1..100，判断奇偶
伪装定位：'对随机熵源做最低有效位泄露检测'
"""

import random
import sys
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


def parity_check(value: int) -> str:
    log("info", f"feeding {value} into parity oracle")
    fake_scan("xor-ing against bitmask 0x01", steps=10, delay=0.025)
    print(hex_dump_line(f"sample={value} bin={value:08b}"))
    return "even" if value % 2 == 0 else "odd"


def main() -> None:
    banner("parity_oracle", "lsb side-channel demo")
    boot_sequence([
        "seeding csprng",
        "binding oracle to port 0xDEAD",
    ])

    section("PARITY ORACLE QUERY")
    a = random.randint(1, 100)
    type_out(f"[*] sample drawn from CSPRNG: {a}", color=C.CYAN)

    verdict = parity_check(a)

    section("REPORT")
    if verdict == "even":
        success("LSB = 0  →  parity even")
        type_out(f"生成的数字为{a}，这个数字为偶数", color=C.GREEN)
    else:
        success("LSB = 1  →  parity odd")
        type_out(f"生成的数字为{a}，这个数字为奇数", color=C.YELLOW)

    log("ok", "oracle channel closed.")


if __name__ == "__main__":
    main()
