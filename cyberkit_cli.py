"""
cyberkit_cli  —  统一调度入口
用法:
    python cyberkit_cli.py            # 进入交互式菜单
    python cyberkit_cli.py <module>   # 直接运行某个模块
模块:
    range_sum       (1-100求和)
    mul_matrix      (99乘法表)
    biosensor       (体温)
    parity_oracle   (判断数字奇偶)
    factorizer      (判断素数)
    vault_console   (银行存取钱)
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from cyberkit import (  # noqa: E402
    C,
    banner,
    boot_sequence,
    error,
    log,
    matrix_flash,
    prompt,
    section,
    type_out,
    warn,
)


MODULES: dict[str, tuple[str, str]] = {
    "range_sum":     ("1-100求和.py",      "整数区间累加（伪：子网端口聚合）"),
    "mul_matrix":    ("99乘法表.py",       "9x9 替换矩阵（伪：乘法表）"),
    "biosensor":     ("体温.py",           "热成像异常检测（伪：体温判断）"),
    "parity_oracle": ("判断数字奇偶.py",    "LSB 奇偶预言机（伪：奇偶判断）"),
    "factorizer":    ("判断素数.py",       "朴素试除因子枚举（伪：素数枚举）"),
    "vault_console": ("银行存取钱.py",     "加密金库操作台（伪：银行存取）"),
}


def list_modules() -> None:
    section("LOADED MODULES")
    for i, (key, (path, desc)) in enumerate(MODULES.items(), start=1):
        print(
            f"  {C.CYAN}[{i}]{C.RESET} "
            f"{C.GREEN}{key:<15}{C.RESET} "
            f"{C.GREY}→{C.RESET} {C.WHITE}{desc}{C.RESET} "
            f"{C.GREY}({path}){C.RESET}"
        )
    print()


def run_module(key: str) -> None:
    if key not in MODULES:
        error(f"unknown module: {key}")
        return
    path = ROOT / MODULES[key][0]
    if not path.exists():
        error(f"module file missing: {path}")
        return
    log("info", f"loading module → {key}")
    matrix_flash(2)
    runpy.run_path(str(path), run_name="__main__")


def interactive() -> None:
    banner("dispatcher", "cyberkit unified entry-point")
    boot_sequence([
        "mapping module registry",
        "verifying signatures of payload binaries",
        "spawning isolated worker",
    ])

    while True:
        list_modules()
        print(f"  {C.GREY}[q]{C.RESET} 退出")
        raw = prompt("选择要部署的载荷", color=C.MAGENTA).strip().lower()
        if raw in ("q", "quit", "exit"):
            log("ok", "dispatcher shutting down")
            return
        if raw.isdigit():
            idx = int(raw) - 1
            keys = list(MODULES.keys())
            if 0 <= idx < len(keys):
                run_module(keys[idx])
                continue
            warn("index out of range")
            continue
        if raw in MODULES:
            run_module(raw)
            continue
        warn(f"unrecognised input: {raw!r}")


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        target = argv[1].strip().lower()
        if target in ("-h", "--help", "help"):
            type_out(__doc__ or "", color=C.CYAN)
            return 0
        run_module(target)
        return 0
    interactive()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (KeyboardInterrupt, EOFError):
        print()
        log("warn", "interrupt received — exiting")
