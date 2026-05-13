"""
modules/vault_console  —  Encrypted Vault Console
原始任务：模拟银行存取款（查询 / 存款 / 取款 / 退出）
伪装定位：'登入加密金库，对资产执行 read/credit/debit 操作'
"""

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
    prompt,
    section,
    success,
    type_out,
    warn,
)


class Vault:
    def __init__(self, owner: str, balance: int):
        self.owner = owner
        self.balance = balance

    def check(self) -> None:
        log("info", "issuing READ on ledger")
        fake_scan("decrypting balance frame", steps=10, delay=0.02)
        print(hex_dump_line(f"owner={self.owner} bal={self.balance}"))
        type_out(f"你的余额：{self.balance}", color=C.GREEN)

    def deposit(self) -> None:
        log("info", "issuing CREDIT on ledger")
        type_out(f"你的余额：{self.balance}", color=C.CYAN)
        raw = prompt("请输入你想存入的金额", color=C.GREEN)
        try:
            amount = int(raw)
        except ValueError:
            error("invalid amount — transaction aborted")
            return
        if amount <= 0:
            warn("non-positive credit rejected")
            return
        fake_scan("appending signed tx-block", steps=12, delay=0.02)
        self.balance += amount
        success(f"+{amount} committed")
        type_out(f"你的余额：{self.balance}", color=C.GREEN)

    def withdraw(self) -> None:
        log("info", "issuing DEBIT on ledger")
        type_out(f"你的余额：{self.balance}", color=C.CYAN)
        raw = prompt("请输入你想取出的金额", color=C.YELLOW)
        try:
            amount = int(raw)
        except ValueError:
            error("invalid amount — transaction aborted")
            return
        if amount <= 0:
            warn("non-positive debit rejected")
            return
        if amount > self.balance:
            error("INSUFFICIENT FUNDS — rollback triggered")
            type_out(f"余额不足，你的余额为{self.balance}", color=C.RED)
            return
        fake_scan("signing debit with HSM key 0xC0DE", steps=12, delay=0.02)
        self.balance -= amount
        success(f"-{amount} committed")
        type_out(f"你的余额：{self.balance}", color=C.GREEN)


def menu() -> None:
    print(f"\n{C.GREEN}+{'-' * 38}+{C.RESET}")
    print(f"{C.GREEN}|{C.RESET}  {C.BOLD}VAULT OPS — encrypted-channel only{C.RESET}  {C.GREEN}|{C.RESET}")
    print(f"{C.GREEN}+{'-' * 38}+{C.RESET}")
    print(f"  {C.CYAN}[1]{C.RESET} 查询余额        (read-ledger)")
    print(f"  {C.CYAN}[2]{C.RESET} 存款            (credit)")
    print(f"  {C.CYAN}[3]{C.RESET} 取款            (debit)")
    print(f"  {C.CYAN}[4]{C.RESET} 退出            (logout & wipe session)")


def main() -> None:
    banner("vault_console", "encrypted-ledger operator shell")
    boot_sequence([
        "establishing TLS 1.3 tunnel to vault.local",
        "verifying HSM attestation",
        "unlocking ledger with operator key",
    ])

    section("VAULT LOGIN")
    name = prompt("请输入你的姓名", color=C.CYAN)
    vault = Vault(owner=name or "anon", balance=50_000_000)
    success(f"welcome, {C.BOLD}{vault.owner}{C.RESET} — session attached to ledger#0x{id(vault) & 0xFFFFFF:06X}")

    while True:
        menu()
        raw = prompt("选择操作 (1-4)", color=C.MAGENTA)
        if not raw.strip().isdigit():
            warn("non-numeric choice ignored")
            continue
        choice = int(raw)
        if choice == 1:
            vault.check()
        elif choice == 2:
            vault.deposit()
        elif choice == 3:
            vault.withdraw()
        elif choice == 4:
            section("LOGOUT")
            fake_scan("wiping session keys from RAM", steps=14, delay=0.025)
            log("ok", "channel closed. goodbye.")
            break
        else:
            warn(f"unknown opcode: {choice}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
        log("warn", "operator aborted — session torn down")
