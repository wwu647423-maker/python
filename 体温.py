"""
modules/biosensor  —  Thermal Biometric Anomaly Detector
原始任务：随机生成体温并判断是否发烧
伪装定位：'对目标生物体征做异常检测，触发隔离协议'
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cyberkit import (
    C,
    banner,
    boot_sequence,
    error,
    fake_scan,
    hex_dump_line,
    log,
    section,
    success,
    type_out,
    warn,
)

THRESHOLD = 37.0


def check(data: float) -> None:
    log("info", f"sampling thermal signature — raw = {data:.2f}°C")
    fake_scan("evaluating against baseline 37.0°C", steps=12, delay=0.02)
    print(hex_dump_line(f"temp={data:.2f}"))

    if data > THRESHOLD:
        error("ANOMALY DETECTED — subject exceeds threshold")
        type_out(f"你的体温是{data}，你发烧了", color=C.RED)
        warn("triggering quarantine protocol [SIM-ONLY]")
    else:
        success("subject within nominal range")
        type_out(f"你的体温是{data}，你的体温正常", color=C.GREEN)


def main() -> None:
    banner("biosensor", "thermal anomaly detection")
    boot_sequence([
        "linking to /dev/biosensor0",
        "loading WHO baseline tables",
        "warming up IR module",
    ])

    section("BIOMETRIC SCAN")
    type_out("[*] target       = unknown subject", color=C.CYAN)
    type_out("[*] sensor       = IR thermal v3", color=C.CYAN)
    type_out(f"[*] threshold_°C = {THRESHOLD}", color=C.CYAN)

    tem = random.randint(36, 40)
    check(tem)

    section("REPORT")
    log("ok", "scan finalised. data committed to evidence vault.")


if __name__ == "__main__":
    main()
