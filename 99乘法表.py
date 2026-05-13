"""
modules/mul_matrix  —  9x9 Cipher Matrix Generator
原始任务：打印九九乘法表
伪装定位：'生成 9x9 替换密码矩阵'
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cyberkit import C, banner, boot_sequence, fake_scan, log, section, type_out


def render_matrix(size: int = 9) -> None:
    log("info", f"deriving substitution matrix of order {size}")
    fake_scan("seeding finite-field tables", steps=12, delay=0.02)

    print(f"\n{C.GREEN}      cipher-matrix dump (mod 0):{C.RESET}\n")
    for i in range(1, size + 1):
        line_parts = []
        for j in range(1, i + 1):
            cell = f"{C.CYAN}{i}{C.GREY}*{C.CYAN}{j}{C.GREY}={C.WHITE}{i*j}{C.RESET}"
            line_parts.append(cell)
            print(f"{cell}\t", end="")
            time.sleep(0.004)
        print()
    print()
    log("ok", "matrix materialised — 45 cells written to stdout buffer")


def main() -> None:
    banner("mul_matrix", "9x9 substitution-table builder")
    boot_sequence([
        "loading numeric field GF(9)",
        "verifying lattice symmetry",
    ])

    section("CIPHER MATRIX GENERATION")
    type_out("[*] order      = 9", color=C.CYAN)
    type_out("[*] op         = multiplicative", color=C.CYAN)
    type_out("[*] layout     = lower-triangular", color=C.CYAN)

    render_matrix(9)

    section("REPORT")
    log("ok", "no anomalies detected. matrix integrity = nominal")


if __name__ == "__main__":
    main()
