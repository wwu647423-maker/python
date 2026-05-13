"""
CyberKit / UI — ANSI 配色、横幅、伪扫描动画、模拟日志。
让一段平平无奇的脚本看起来像是在做渗透测试。
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
import time
from datetime import datetime


class C:
    """ANSI 颜色常量。终端不支持时会自动降级为空字符串。"""

    _ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @staticmethod
    def _w(code: str) -> str:
        return code if C._ENABLED else ""

    RESET = ""
    BOLD = ""
    DIM = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    WHITE = ""
    GREY = ""


def _init_colors() -> None:
    if not C._ENABLED:
        return
    C.RESET = "\033[0m"
    C.BOLD = "\033[1m"
    C.DIM = "\033[2m"
    C.RED = "\033[31m"
    C.GREEN = "\033[32m"
    C.YELLOW = "\033[33m"
    C.BLUE = "\033[34m"
    C.MAGENTA = "\033[35m"
    C.CYAN = "\033[36m"
    C.WHITE = "\033[97m"
    C.GREY = "\033[90m"


_init_colors()


BANNER = r"""
   ____      _               _  ___ _
  / ___|   _| |__   ___ _ __| |/ (_) |_
 | |  | | | | '_ \ / _ \ '__| ' /| | __|
 | |__| |_| | |_) |  __/ |  | . \| | |_
  \____\__, |_.__/ \___|_|  |_|\_\_|\__|
       |___/   //  red-team operator console
"""


def _stamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _session_id() -> str:
    seed = f"{os.getpid()}-{time.time()}-{random.random()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16].upper()


SESSION = _session_id()


def banner(module_name: str = "core", tagline: str = "") -> None:
    """打印黑客风启动横幅。"""
    sys.stdout.write(f"{C.GREEN}{BANNER}{C.RESET}")
    sys.stdout.write(
        f"{C.GREY} session  : {C.CYAN}{SESSION}{C.RESET}\n"
        f"{C.GREY} module   : {C.WHITE}{module_name}{C.RESET}\n"
        f"{C.GREY} operator : {C.WHITE}{os.environ.get('USER', 'r00t')}@cyberkit{C.RESET}\n"
        f"{C.GREY} kernel   : {C.WHITE}{sys.platform}/py{sys.version_info.major}.{sys.version_info.minor}{C.RESET}\n"
    )
    if tagline:
        sys.stdout.write(f"{C.GREY} payload  : {C.MAGENTA}{tagline}{C.RESET}\n")
    sys.stdout.write(f"{C.GREEN}{'-' * 56}{C.RESET}\n")
    sys.stdout.flush()


def log(level: str, msg: str) -> None:
    """统一格式的日志行。level: info/ok/warn/err/dbg"""
    palette = {
        "info": (C.CYAN, "INFO"),
        "ok": (C.GREEN, " OK "),
        "warn": (C.YELLOW, "WARN"),
        "err": (C.RED, "ERR!"),
        "dbg": (C.MAGENTA, "DBG "),
    }
    color, tag = palette.get(level, (C.WHITE, level.upper()[:4]))
    print(
        f"{C.GREY}[{_stamp()}]{C.RESET} "
        f"{color}[{tag}]{C.RESET} "
        f"{C.GREY}{SESSION}{C.RESET}  {msg}"
    )


def success(msg: str) -> None:
    log("ok", msg)


def warn(msg: str) -> None:
    log("warn", msg)


def error(msg: str) -> None:
    log("err", msg)


def section(title: str) -> None:
    bar = "═" * 56
    print(f"\n{C.GREEN}╔{bar}╗{C.RESET}")
    print(f"{C.GREEN}║{C.RESET} {C.BOLD}{C.WHITE}{title.center(54)}{C.RESET} {C.GREEN}║{C.RESET}")
    print(f"{C.GREEN}╚{bar}╝{C.RESET}")


def type_out(text: str, delay: float = 0.012, color: str = "") -> None:
    """逐字打印。终端非交互式时一次性输出。"""
    if not C._ENABLED:
        print(f"{color}{text}{C.RESET}")
        return
    sys.stdout.write(color)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(C.RESET + "\n")


def fake_scan(label: str, steps: int = 18, delay: float = 0.04) -> None:
    """伪装的扫描/连接进度条。"""
    width = 32
    for i in range(steps + 1):
        ratio = i / steps
        filled = int(width * ratio)
        bar = "█" * filled + "░" * (width - filled)
        pct = int(ratio * 100)
        sys.stdout.write(
            f"\r{C.GREY}[{_stamp()}]{C.RESET} "
            f"{C.CYAN}[SCAN]{C.RESET} {label:<28} "
            f"{C.GREEN}{bar}{C.RESET} {pct:3d}%"
        )
        sys.stdout.flush()
        time.sleep(delay if C._ENABLED else 0)
    sys.stdout.write("\n")


def boot_sequence(targets: list[str] | None = None) -> None:
    """启动模拟：加载模块、握手、密钥协商。"""
    targets = targets or [
        "loading payload modules",
        "negotiating tls handshake",
        "deploying syscall hooks",
        "decrypting local vault",
        "binding shell to /dev/null",
    ]
    for t in targets:
        fake_scan(t, steps=14, delay=0.025)
    success("environment ready — entering interactive shell")


def hex_dump_line(value: object) -> str:
    """把任意对象渲染成假装很专业的 hex+ascii 行。"""
    raw = str(value).encode("utf-8", errors="replace")
    hexpart = " ".join(f"{b:02x}" for b in raw[:16]).ljust(48)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:16])
    digest = hashlib.md5(raw).hexdigest()[:8]
    return f"{C.GREY}{digest}{C.RESET}  {C.CYAN}{hexpart}{C.RESET}  |{C.WHITE}{ascii_part}{C.RESET}|"


def matrix_flash(lines: int = 4, width: int = 56) -> None:
    """快速闪过几行随机字符，制造"正在解密"的氛围。"""
    if not C._ENABLED:
        return
    charset = "01アイウエオカキクケコサシスセソタチツテト$#%&*+=-"
    for _ in range(lines):
        s = "".join(random.choice(charset) for _ in range(width))
        sys.stdout.write(f"{C.GREEN}{s}{C.RESET}\n")
        sys.stdout.flush()
        time.sleep(0.04)


def prompt(label: str, color: str = "") -> str:
    """带提示符的 input()。"""
    color = color or C.CYAN
    return input(f"{C.GREY}┌─[{C.RESET}{color}operator@cyberkit{C.RESET}{C.GREY}]─[{C.RESET}{C.WHITE}{label}{C.RESET}{C.GREY}]\n└──╼ $ {C.RESET}")
