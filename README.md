# CyberKit

A small, **pure-stdlib** offensive-security toolkit. Nine focused tools
behind one dispatcher, no third-party dependencies, machine-readable
`--json` output everywhere it makes sense.

```
$ python -m cyberkit -h
cyberkit  —  pure-stdlib offensive-security toolkit  (v0.2.0)

subcommands:
  portscan    Concurrent TCP connect scanner with banner grab
  hashid      Identify hash type from length/charset/structure
  hashcrack   Wordlist crack of md5/sha1/sha256/sha512/ntlm
  pwdaudit    Password strength + HIBP k-anonymity breach lookup
  httpprobe   HTTP fingerprinting & tech detection
  jwtinspect  Decode JWTs; flag alg=none; brute HS256 secrets
  xorcrack    XOR encrypt/decrypt; single-byte and repeating-key recovery
  entropy     Shannon entropy of a file with windowed analysis
  hexview     Hex+ASCII dump with offset/length controls
```

Requirements: Python ≥ 3.9. Nothing to `pip install`.

> ⚠️ For authorized testing, CTFs, and your own infrastructure only.

---

## Tools

### `portscan` — concurrent TCP connect scanner

Threaded TCP-connect scanner (no raw sockets, no root). Supports flexible
port specs (`22,80,443`, `1-1024`, `top100`, `all`), protocol-aware
banner grabbing for common services, TLS inspection (cert CN/SAN, proto,
cipher) on 443/8443/9443, and JSON-Lines output.

```bash
python -m cyberkit portscan scanme.nmap.org -p top100 -w 200 -t 1.0
python -m cyberkit portscan 10.0.0.5 -p 1-65535 --json | jq .
```

### `hashid` — identify a hash

Identifies algorithms by length + charset + structural prefixes (`$2b$`,
`$argon2id$`, `$6$`, …). Returns ranked candidates so you can iterate.

```bash
python -m cyberkit hashid 5d41402abc4b2a76b9719d911017c592
python -m cyberkit hashid '$2b$12$Eix...' --json
```

### `hashcrack` — wordlist hash recovery

Cracks unsalted (or simply-salted, prepend/append) hashes against a
wordlist. Supports `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`,
and `ntlm`. NTLM uses a bundled pure-Python MD4 because modern OpenSSL
removes the legacy provider.

```bash
python -m cyberkit hashcrack 8846f7eaee8fb117ad06bdd830b7586c \
                              -a ntlm -w cyberkit/data/passwords-small.txt
echo -e "alice\nbob\ncharlie" | python -m cyberkit hashcrack <md5hex> -a md5
```

### `pwdaudit` — local audit + HIBP breach lookup

Local checks: length, charset diversity, Shannon entropy, common-base
detection (incl. leet-speak), keyboard runs, repeated chars, year
patterns, estimated guess-entropy with pattern penalties → score 0–4.

Online check (opt-out via `--offline`): k-anonymous HIBP lookup — only
the first 5 chars of `SHA1(password)` ever leave your machine.

```bash
python -m cyberkit pwdaudit "Tr0ub4dor&3"
python -m cyberkit pwdaudit --offline --json "letmein"
```

### `httpprobe` — HTTP fingerprinting

For each URL: status, server, page title, content-type, technology
fingerprint (signature ruleset across headers/body — nginx, Apache,
Cloudflare, PHP, Laravel, WordPress, Drupal, Next.js, …), and a list of
**missing security headers** (`HSTS`, CSP, `X-Frame-Options`, …).

```bash
python -m cyberkit httpprobe https://example.com https://github.com
cat urls.txt | python -m cyberkit httpprobe --json -w 32
```

### `jwtinspect` — JWT decode + audit + brute

* Decodes header/payload (handles missing base64 padding).
* Flags `alg=none` (auth-bypass class), missing `exp`, expired tokens,
  asymmetric algs without `kid`, missing `iss`/`sub`.
* Verifies HS256/HS384/HS512 signatures against `--secret`.
* Brute-forces HMAC secrets with `--brute wordlist.txt` — offline, pure
  HMAC, no network.

```bash
python -m cyberkit jwtinspect "$JWT"
python -m cyberkit jwtinspect "$JWT" --brute cyberkit/data/passwords-small.txt
```

### `xorcrack` — XOR cipher tooling

* `crypt`: encrypt/decrypt with a known key (XOR is symmetric).
* `brute-single`: try all 256 single-byte keys; rank plaintexts by
  English letter frequency.
* `brute-repeating`: recover an unknown multi-byte repeating key —
  estimate keysize via normalized Hamming distance, solve each column
  independently, then reduce the result to its smallest period.

```bash
echo -n 'attack at dawn' | python -m cyberkit xorcrack crypt -k 'ICE' --hex-out
python -m cyberkit xorcrack brute-single -i ct.bin
python -m cyberkit xorcrack brute-repeating -i ct.bin --kmax 40
```

### `entropy` — Shannon entropy with windowed view

Global entropy + a per-window series rendered as an ASCII spark-line so
you can see at a glance whether a file is text, executable, compressed,
or encrypted.

```bash
python -m cyberkit entropy ./suspicious.bin
python -m cyberkit entropy ./suspicious.bin -w 1024 --json
```

### `hexview` — clean hex+ASCII dump

`hexdump -C` layout, optional offset/length, color when stdout is a TTY.

```bash
python -m cyberkit hexview /bin/ls -n 256
python -m cyberkit hexview /bin/ls -o 0x1000 -n 64
```

---

## Project layout

```
cyberkit/
  __init__.py
  __main__.py        # dispatcher
  _common.py         # shared output helpers
  _md4.py            # pure-Python MD4 (for NTLM; verified against RFC 1320)
  portscan.py
  hashid.py
  hashcrack.py
  pwdaudit.py
  httpprobe.py
  jwtinspect.py
  xorcrack.py
  entropy.py
  hexview.py
  data/
    passwords-small.txt
    dirs-small.txt
tests/
  test_*.py          # 52 unit tests; run with `python -m unittest`
```

## Running the test suite

```bash
python -m unittest discover -s tests -v
```

Covers: hash identification, hash cracking (md5/sha1/sha256/sha512/ntlm,
prepend/append salt), password strength heuristics, JWT decode +
verify + brute + `alg=none` audit, XOR self-inverse, single-byte +
repeating-key recovery, Hamming-distance keysize estimation, entropy
sanity properties (constant=0, two-valued=1, urandom≈8), hexview layout,
port-spec parsing, and a live in-process port scan.

## Conventions

* `--json` produces JSON (single document or JSON-Lines, depending on
  the tool) for piping into `jq`/automation.
* `NO_COLOR=1` disables ANSI escapes; piping to a file/pipe also does.
* Every tool exits non-zero on operational failure (cracking miss,
  network error, parse error) so it works in shell pipelines.

## License

Use it. Don't be a jerk with it.
