# CyberKit

A **pure-stdlib** offensive-security toolkit. Fourteen focused tools
behind one dispatcher, no third-party dependencies, machine-readable
`--json` output everywhere it makes sense.

```
$ python -m cyberkit -h
cyberkit  —  pure-stdlib offensive-security toolkit  (v0.3.0)

subcommands:
  portscan     Concurrent TCP connect scanner with banner grab
  dnsenum      DNS recon: record dump, AXFR, subdomain brute
  dirfuzz      HTTP content discovery with 404 fingerprinting
  httpprobe    HTTP fingerprinting & tech detection
  certinspect  TLS certificate inspection & expiry / hostname checks
  hashid       Identify hash type from length/charset/structure
  hashcrack    Wordlist crack of md5/sha1/sha256/sha512/ntlm (+--rules)
  pwdaudit     Password strength + HIBP k-anonymity breach lookup
  jwtinspect   Decode JWTs; flag alg=none; brute HS256 secrets
  xorcrack     XOR encrypt/decrypt; single-byte and repeating-key recovery
  baseconv     Encode / decode / auto-detect base16/32/58/64/85/url/rot
  secrets      Scan files/dirs for hardcoded credentials and tokens
  entropy      Shannon entropy of a file with windowed analysis
  hexview      Hex+ASCII dump with offset/length controls
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

### `dnsenum` — DNS reconnaissance

Built on a pure-stdlib RFC 1035 resolver (UDP queries + TCP AXFR; full
name-compression support and bounded recursion). Dumps A / AAAA / NS /
MX / TXT / SOA / CNAME by default, optionally attempts AXFR against
each authoritative NS, and runs concurrent wordlist subdomain enum with
wildcard-DNS detection so wildcard zones don't poison results.

```bash
python -m cyberkit dnsenum example.com
python -m cyberkit dnsenum example.com --axfr --brute cyberkit/data/dirs-small.txt
python -m cyberkit dnsenum example.com --types A,AAAA,MX -s 8.8.8.8 --json
```

### `dirfuzz` — HTTP content discovery

Concurrent wordlist content fuzzer with **smart 404 fingerprinting**:
two random made-up probes calibrate the not-found shape (status + body
length + title), and matching responses are filtered out. Defeats the
common soft-404 problem where apps return 200 OK on missing paths.

```bash
python -m cyberkit dirfuzz https://target.example.com
python -m cyberkit dirfuzz https://target.example.com -w bigwordlist.txt -T 64
```

### `certinspect` — TLS certificate inspection

TLS handshake to a `host:port`, parses the leaf cert (even when invalid
or self-signed — uses `_ssl._test_decode_cert` on the raw DER so we can
inspect expired / mismatched / self-signed certs). Reports protocol,
cipher, subject, issuer, SANs, validity window, days-to-expiry (with
HIGH/CRITICAL gates), self-signed flag, and hostname-match check.

```bash
python -m cyberkit certinspect example.com
python -m cyberkit certinspect mail.example.com:993 --sni mail.example.com --json
```

### `hashid` — identify a hash

Identifies algorithms by length + charset + structural prefixes (`$2b$`,
`$argon2id$`, `$6$`, …). Returns ranked candidates so you can iterate.

```bash
python -m cyberkit hashid 5d41402abc4b2a76b9719d911017c592
python -m cyberkit hashid '$2b$12$Eix...' --json
```

### `hashcrack` — wordlist hash recovery + rule engine

Cracks unsalted (or simply-salted, prepend/append) hashes against a
wordlist. Supports `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`,
and `ntlm` (NTLM uses a bundled pure-Python MD4 because modern OpenSSL
removes the legacy provider). With `--rules`, each wordlist entry is
expanded with common hashcat-style mutations: case toggles, digit /
year / symbol suffixes, leet substitutions, reversed forms — so a 100-
entry list yields thousands of candidates.

```bash
python -m cyberkit hashcrack 8846f7eaee8fb117ad06bdd830b7586c \
                              -a ntlm -w cyberkit/data/passwords-small.txt
python -m cyberkit hashcrack <md5hex> -a md5 --rules -w cyberkit/data/passwords-small.txt
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
fingerprint (40+ signature rules across headers and body — nginx,
Apache, Caddy, IIS, LiteSpeed, Kestrel, gunicorn, uvicorn, Flask,
Cloudflare, CloudFront, Vercel, Netlify, Render, Varnish, PHP, Laravel,
ASP.NET (MVC), Express, Django, Java/JSP, WordPress, Drupal, Joomla,
Next.js, Nuxt, React, Vue, Angular, Svelte, jQuery, GraphQL, Magento,
Shopify, Ghost), and a list of **missing security headers** (HSTS, CSP,
`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`). If you omit the scheme, HTTPS is tried first
with HTTP fallback.

```bash
python -m cyberkit httpprobe example.com github.com         # HTTPS-first
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

### `baseconv` — multi-encoding swiss army knife

Encode / decode base16, base32, base58 (Bitcoin alphabet), base64,
base64url, base85, URL, HTML entities, and ROT-N. The `auto` mode tries
every decoder + every rot shift and ranks the candidates by how
English-like the result looks, so multi-layer CTF chains unpeel
themselves.

```bash
python -m cyberkit baseconv encode base64 -i "hello world"
echo "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==" \
    | python -m cyberkit baseconv auto
echo "gur dhvpx oebja sbk" | python -m cyberkit baseconv auto       # rot13 wins
```

### `secrets` — hardcoded-credential scanner

Walks a directory tree and runs a curated rule table against every text
file. Rules cover AWS, GCP, GitHub PAT/OAuth/App/Fine-grained, Slack
tokens & webhooks, Stripe live / restricted, Google API & OAuth, Heroku,
Twilio, SendGrid, Mailgun, npm, OpenAI, JWTs, PEM private-key blocks,
context-aware generic API keys (with min-entropy gating to suppress
false positives), password assignments, URLs with embedded credentials.
Skips `.git`, `node_modules`, `__pycache__`, virtualenvs, build/dist,
common binary formats. Matches are redacted by default.

```bash
python -m cyberkit secrets .
python -m cyberkit secrets ./src --no-redact --min-severity HIGH --json
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
  __main__.py        # dispatcher (14 subcommands)
  _common.py         # shared output helpers
  _md4.py            # pure-Python MD4 (NTLM; verified against RFC 1320)
  _dns.py            # pure-stdlib DNS-over-UDP resolver + TCP AXFR
  portscan.py
  dnsenum.py
  dirfuzz.py
  httpprobe.py
  certinspect.py
  hashid.py
  hashcrack.py
  pwdaudit.py
  jwtinspect.py
  xorcrack.py
  baseconv.py
  secrets.py
  entropy.py
  hexview.py
  data/
    passwords-small.txt
    dirs-small.txt
tests/
  test_*.py          # 99 unit tests; run with `python -m unittest`
```

## Running the test suite

```bash
python -m unittest discover -s tests -v
```

Covers, in addition to the original tools: DNS name encoding/decoding
with compression-pointer loops, A/AAAA/MX/TXT/NXDOMAIN/truncated-packet
parsing; hashcrack mutation engine (case, suffix, leet, reverse) +
rule-driven cracking; secret scanner regex + entropy + redaction; base16/
32/58/64/85 round-trips, base58 leading-zero handling, rot13 involution,
base64 and rot13 auto-detection; dirfuzz 404 fingerprint calibration and
hit filtering against a real in-process server.

## Conventions

* `--json` produces JSON (single document or JSON-Lines, depending on
  the tool) for piping into `jq`/automation.
* `NO_COLOR=1` disables ANSI escapes; piping to a file/pipe also does.
* Every tool exits non-zero on operational failure (cracking miss,
  network error, parse error) so it works in shell pipelines.

## License

Use it. Don't be a jerk with it.
