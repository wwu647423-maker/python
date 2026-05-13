"""CyberKit - Offensive-style toolbox wrapper for everyday scripts."""

from .ui import (
    C,
    banner,
    boot_sequence,
    fake_scan,
    hex_dump_line,
    log,
    prompt,
    section,
    success,
    warn,
    error,
    type_out,
    matrix_flash,
)

__all__ = [
    "C",
    "banner",
    "boot_sequence",
    "fake_scan",
    "hex_dump_line",
    "log",
    "prompt",
    "section",
    "success",
    "warn",
    "error",
    "type_out",
    "matrix_flash",
]

__version__ = "0.1.0-alpha"
__author__ = "r00t@cyberkit"
