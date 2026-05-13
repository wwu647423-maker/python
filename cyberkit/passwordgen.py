"""
passwordgen — cryptographically-strong password / passphrase generation.

Backed entirely by `secrets` (the stdlib CSPRNG-backed module, not our
unrelated `cyberkit.secrets` scanner — note the qualified import).

Modes:
  rand        random N-char password from chosen classes
  pass        EFF-style diceware passphrase, N words joined by a separator
  pin         numeric PIN of given length

The `rand` mode guarantees at least one character from every selected
class (lower / upper / digit / symbol) so policy checks pass on the first
try, but the *positions* of the guaranteed characters are themselves
randomized so the output is still uniform.
"""

from __future__ import annotations

import argparse
import math
import secrets as _csprng
import string
import sys

from ._common import bold, cyan, dim, emit_json, green

AMBIGUOUS = set("Il1O0o`'\"|")

DEFAULT_WORDS = [
    "abacus", "abdomen", "ability", "abolish", "absence", "abstract", "academy",
    "accent", "access", "account", "achieve", "acid", "across", "action",
    "active", "actor", "actual", "adapt", "address", "admire", "adult",
    "advance", "affair", "afford", "afraid", "after", "agent", "agree",
    "ahead", "airline", "airport", "album", "alert", "alley", "allow",
    "almond", "almost", "alone", "along", "alpha", "already", "always",
    "amaze", "amber", "ample", "anchor", "ancient", "angle", "animal",
    "annual", "answer", "antique", "anvil", "apartment", "apology", "appear",
    "apple", "arcade", "arctic", "argue", "armor", "around", "arrest",
    "arrow", "artist", "aspect", "assist", "atom", "attempt", "auction",
    "august", "author", "autumn", "avenue", "avoid", "awake", "aware",
    "axis", "azure", "balcony", "ballet", "banana", "banjo", "barley",
    "basic", "basket", "battle", "beacon", "beauty", "become", "begin",
    "behave", "behind", "belong", "berry", "beside", "better", "beyond",
    "binary", "biology", "biscuit", "bitter", "blanket", "blast", "bless",
    "blizzard", "blossom", "bolt", "bonus", "border", "bottle", "boulder",
    "bounce", "bracket", "branch", "brave", "bread", "breeze", "bridge",
    "brick", "bright", "broken", "bronze", "brush", "bubble", "bucket",
    "buffer", "burden", "burst", "busy", "butter", "button", "cabin",
    "cactus", "camera", "candle", "canopy", "canvas", "canyon", "capture",
    "career", "carpet", "carrier", "casino", "castle", "catalog", "ceiling",
    "celery", "cello", "center", "cereal", "champion", "chapter", "charm",
    "cheese", "cherry", "chess", "chief", "circle", "citizen", "civil",
    "classic", "clever", "client", "clinic", "clock", "closet", "cloud",
    "clutch", "coach", "coastal", "cobra", "coffee", "column", "comet",
    "comic", "commit", "compass", "concept", "conduct", "confess", "conifer",
    "consul", "contact", "convert", "coral", "corner", "cosmic", "cotton",
    "courage", "cousin", "cradle", "crater", "create", "credit", "crystal",
    "cube", "culture", "current", "custom", "cycle", "dagger", "daily",
    "dance", "danger", "daring", "dawn", "decade", "decimal", "decree",
    "defend", "define", "degree", "delete", "demand", "denial", "depart",
    "depend", "deploy", "depth", "describe", "design", "desire", "detail",
    "detect", "device", "diamond", "diary", "differ", "dinner", "direct",
    "discount", "dispute", "distant", "doctor", "dolphin", "domain", "donate",
    "donkey", "double", "doubt", "dozen", "draft", "dragon", "drama",
]


def _shuffle(items: list[str]) -> list[str]:
    items = list(items)
    for i in range(len(items) - 1, 0, -1):
        j = _csprng.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]
    return items


def gen_random(length: int, lower: bool = True, upper: bool = True,
               digit: bool = True, symbol: bool = True,
               no_ambiguous: bool = False) -> str:
    pools = []
    if lower: pools.append(string.ascii_lowercase)
    if upper: pools.append(string.ascii_uppercase)
    if digit: pools.append(string.digits)
    if symbol: pools.append("!@#$%^&*()-_=+[]{};:,.?/")
    if not pools:
        raise ValueError("at least one character class must be enabled")
    if no_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
        pools = [p for p in pools if p]
    if length < len(pools):
        raise ValueError(f"length {length} < {len(pools)} required classes")
    chosen = [_csprng.choice(p) for p in pools]
    all_chars = "".join(pools)
    chosen += [_csprng.choice(all_chars) for _ in range(length - len(pools))]
    return "".join(_shuffle(chosen))


def gen_passphrase(words: int, sep: str = "-", capitalize: bool = False,
                   add_digit: bool = False, wordlist: list[str] | None = None) -> str:
    wl = wordlist or DEFAULT_WORDS
    picks = [_csprng.choice(wl) for _ in range(words)]
    if capitalize:
        picks = [w.capitalize() for w in picks]
    out = sep.join(picks)
    if add_digit:
        out += str(_csprng.randbelow(10))
    return out


def gen_pin(length: int) -> str:
    return "".join(str(_csprng.randbelow(10)) for _ in range(length))


def estimate_entropy_bits(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() and not c.isspace() for c in password): pool += 24
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cyberkit passwordgen",
                                 description="Generate strong passwords / passphrases / PINs.")
    sub = ap.add_subparsers(dest="mode", required=True)

    r = sub.add_parser("rand", help="random N-char password")
    r.add_argument("-n", "--length", type=int, default=20)
    r.add_argument("--no-lower", action="store_true")
    r.add_argument("--no-upper", action="store_true")
    r.add_argument("--no-digit", action="store_true")
    r.add_argument("--no-symbol", action="store_true")
    r.add_argument("--no-ambiguous", action="store_true",
                   help="exclude visually-confusable characters (I l 1 O 0 etc.)")
    r.add_argument("-c", "--count", type=int, default=1)
    r.add_argument("--json", action="store_true")

    p = sub.add_parser("pass", help="passphrase")
    p.add_argument("-w", "--words", type=int, default=6)
    p.add_argument("-s", "--separator", default="-")
    p.add_argument("--capitalize", action="store_true")
    p.add_argument("--add-digit", action="store_true")
    p.add_argument("--wordlist", help="custom wordlist (one word per line)")
    p.add_argument("-c", "--count", type=int, default=1)
    p.add_argument("--json", action="store_true")

    pin = sub.add_parser("pin", help="numeric PIN")
    pin.add_argument("-n", "--length", type=int, default=6)
    pin.add_argument("-c", "--count", type=int, default=1)

    args = ap.parse_args(argv)

    if args.mode == "rand":
        try:
            outs = [
                gen_random(
                    length=args.length,
                    lower=not args.no_lower,
                    upper=not args.no_upper,
                    digit=not args.no_digit,
                    symbol=not args.no_symbol,
                    no_ambiguous=args.no_ambiguous,
                )
                for _ in range(args.count)
            ]
        except ValueError as e:
            print(f"passwordgen: {e}", file=sys.stderr); return 2
        if args.json:
            emit_json({"passwords": outs,
                       "entropy_bits": round(estimate_entropy_bits(outs[0]), 2)})
            return 0
        for p in outs:
            print(f"{green(p)}  {dim('(~' + f'{estimate_entropy_bits(p):.1f}' + ' bits)')}")
        return 0

    if args.mode == "pass":
        wl = None
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8") as fh:
                    wl = [w.strip() for w in fh if w.strip()]
            except OSError as e:
                print(f"passwordgen: {e}", file=sys.stderr); return 2
        outs = [
            gen_passphrase(words=args.words, sep=args.separator,
                           capitalize=args.capitalize, add_digit=args.add_digit,
                           wordlist=wl)
            for _ in range(args.count)
        ]
        if args.json:
            emit_json({"passphrases": outs})
            return 0
        for p in outs:
            bits = round(args.words * math.log2(len(wl or DEFAULT_WORDS)), 1)
            print(f"{green(p)}  {dim('(~' + str(bits) + ' bits from ' + str(args.words) + ' words)')}")
        return 0

    if args.mode == "pin":
        for _ in range(args.count):
            print(gen_pin(args.length))
        return 0

    return 2
