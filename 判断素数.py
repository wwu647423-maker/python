"""
modules/factorizer  —  Integer Factor Enumerator
原始任务：枚举整数的所有因子（原脚本逻辑）
伪装定位：'对 RSA 模数做朴素试除，枚举所有因子'
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
    log,
    prompt,
    section,
    success,
    type_out,
    warn,
)


def enumerate_factors(num: int) -> list[int]:
    log("info", f"launching trial-division against modulus N = {num}")
    fake_scan("priming wheel-factorization cache", steps=14, delay=0.02)

    factors: list[int] = []
    i = 1
    while i <= num:
        if num % i == 0:
            factors.append(i)
            print(
                f"  {C.GREY}[hit]{C.RESET} divisor found: "
                f"{C.GREEN}{i}{C.RESET}  "
                f"{C.GREY}(quotient = {num // i}){C.RESET}"
            )
            time.sleep(0.01)
        i += 1
    return factors


def main() -> None:
    banner("factorizer", "naïve trial-division engine")
    boot_sequence([
        "loading Pollard rho fallback",
        "warming up gmp bigint backend",
    ])

    section("FACTORIZATION TARGET")
    raw = prompt("enter modulus", color=C.MAGENTA)
    try:
        num = int(raw.strip() or "0")
    except ValueError:
        warn("non-integer payload rejected — using fallback N = 12")
        num = 12

    if num <= 0:
        warn("non-positive N — coercing to 12")
        num = 12

    type_out(f"[*] N = {num}", color=C.CYAN)
    type_out("[*] strategy = exhaustive trial division", color=C.CYAN)

    factors = enumerate_factors(num)

    section("REPORT")
    if len(factors) == 2:
        success(f"N = {num} appears PRIME — only {{1, {num}}} divide it")
    else:
        warn(f"N = {num} is COMPOSITE — {len(factors)} divisors recovered")
    log("ok", f"factor set = {factors}")


if __name__ == "__main__":
    main()
