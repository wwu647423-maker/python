# CyberKit

A **pure-stdlib** offensive-security toolkit. Twenty-five focused tools
behind one dispatcher, no third-party dependencies, machine-readable
`--json` output everywhere it makes sense.

```
$ python -m cyberkit -h
cyberkit  —  pure-stdlib offensive-security toolkit  (v0.5.0)

subcommands:
  portscan     Concurrent TCP connect scanner with banner grab
  dnsenum      DNS recon: record dump, AXFR, subdomain brute
  mailcheck    Email auth posture: SPF / DMARC / DKIM / MX audit
  subtake      Subdomain takeover detector (dangling CNAME -> SaaS)
  cidr         IPv4 / IPv6 subnet calculator (info/contains/summarize/split)
  whois        WHOIS client (TCP/43) with IANA referral chasing
  dirfuzz      HTTP content discovery with 404 fingerprinting
  httpprobe    HTTP fingerprinting & tech detection
  cspaudit     Audit a Content-Security-Policy header
  certinspect  TLS certificate inspection & expiry / hostname checks
  tlsenum      Enumerate supported TLS versions, ciphers, and features
  hashid       Identify hash type from length/charset/structure
  hashcrack    Wordlist crack of md5/sha1/sha256/sha512/ntlm (+--rules)
  crackzip     Crack ZipCrypto-encrypted .zip files (+--rules)
  pwdaudit     Password strength + HIBP + bundled common-password check
  passwordgen  Generate strong passwords / diceware passphrases / PINs
  otp          TOTP / HOTP generate, verify, otpauth:// parse
  jwtinspect   Decode + audit JWTs (alg=none, kid/jku injection, brute)
  xorcrack     XOR encrypt/decrypt; single-byte and repeating-key recovery
  baseconv     Encode / decode / auto-detect base16/32/58/64/85/url/rot
  secrets      Scan files/dirs for hardcoded credentials and tokens
  packetparse  Decode hex packet captures (Ethernet/IPv4/IPv6/TCP/UDP/DNS)
  pcap         Read libpcap files; protocol histogram / top talkers / per-packet
  entropy      Shannon entropy + magic-byte file-type detection
  hexview      Hex+ASCII dump with offset/length controls
```

Requirements: Python ≥ 3.9. Nothing to `pip install`. **206 unit tests**.

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

Built on a pure-stdlib RFC 1035 resolver (UDP queries with **automatic
TCP fallback on truncation**, plus TCP AXFR; full name-compression
support and bounded recursion). Dumps A / AAAA / NS / MX / TXT / SOA /
CNAME by default, optionally attempts AXFR against each authoritative
NS, and runs concurrent wordlist subdomain enum with wildcard-DNS
detection so wildcard zones don't poison results.

```bash
python -m cyberkit dnsenum example.com
python -m cyberkit dnsenum example.com --axfr --brute cyberkit/data/dirs-small.txt
python -m cyberkit dnsenum example.com --types A,AAAA,MX -s 8.8.8.8 --json
```

### `mailcheck` — email authentication audit

Pulls TXT records via the stdlib resolver and audits the domain's email
auth posture:

* **SPF**: missing, `+all` (CRITICAL — anyone can spoof), `~all` vs `-all`,
  duplicate records (RFC 7208 violation), > 10 DNS-lookup mechanisms
* **DMARC**: missing `_dmarc.<domain>`, weak `p=none`, `pct<100`, missing
  `rua=` aggregate-report endpoint, `sp=none`, relaxed alignment
* **DKIM**: per-selector key inspection (`p=`, `k=`, key length, revoked)
* **MX**: at least one MX with a reachable A record

```bash
python -m cyberkit mailcheck example.com
python -m cyberkit mailcheck example.com --selector default --selector google
```

### `subtake` — subdomain takeover detector

For each subdomain: trace the CNAME chain via our DNS resolver; if it
ends at a known SaaS host (GitHub Pages, Heroku, S3, CloudFront, Azure
CloudApp, Shopify, Fastly, Tumblr, Unbounce, Webflow, Pantheon, Surge,
Bitbucket, Read the Docs, …), HTTP-probe the resource and look for that
service's canonical orphan fingerprint. Flags `VULNERABLE` /
`potential` / `cname-not-service` / `no-cname`.

```bash
echo old.example.com | python -m cyberkit subtake
python -m cyberkit subtake sub1.target.com sub2.target.com --json
```

### `cidr` — subnet calculator

Backed by stdlib `ipaddress`. Subcommands:

* `info`        — network / broadcast / first / last / count / flags
* `contains`    — does CIDR include IP? (exit-code 0/1 for scripts)
* `summarize`   — collapse a list of CIDRs/IPs into the minimal cover
* `split`       — carve a CIDR into smaller /N subnets
* `iter`        — list every address with a `--limit` safety guard

Handles both IPv4 and IPv6 (including /64 — no enumeration; uses index
arithmetic so a `cidr info 2001:db8::/64` returns instantly).

```bash
python -m cyberkit cidr info 10.0.0.0/24
python -m cyberkit cidr summarize 10.0.0.0/25 10.0.0.128/25       # → 10.0.0.0/24
python -m cyberkit cidr split 10.0.0.0/22 26
```

### `whois` — WHOIS lookup with referral chasing

TCP/43 client. Starts at `whois.iana.org`, parses `refer:` / `whois:` /
`ReferralServer:` / `Registrar WHOIS Server:` lines and follows them up
to 4 hops. Speaks the VeriSign `=domain` syntax automatically for .com /
.net referrals.

```bash
python -m cyberkit whois example.com
python -m cyberkit whois 8.8.8.8
python -m cyberkit whois example.io --json
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

### `cspaudit` — Content-Security-Policy auditor

Parses a CSP value into directives and flags unsafe constructs:
`unsafe-inline`, `unsafe-eval`, `unsafe-hashes`, wildcard `*`, bare
`http:`, `data:`/`blob:` in script/object directives, plus missing
critical directives (`script-src` / `object-src` / `base-uri` /
`frame-ancestors`) — escalated to HIGH only when there's no
`default-src` fallback. Source can be `--policy "..."`, `--url`, or
stdin.

```bash
python -m cyberkit cspaudit --url https://example.com
python -m cyberkit cspaudit --policy "default-src 'self'; script-src * 'unsafe-inline'"
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

### `tlsenum` — enumerate TLS versions, ciphers, features

For each candidate TLS version (1.0/1.1/1.2/1.3) we pin
`minimum_version == maximum_version` on a fresh `SSLContext` and try a
handshake. For ciphers we walk a curated list of weak + strong suites
and see what the server is willing to negotiate. Reports flag legacy
protocols (TLS<1.2) and weak ciphers (NULL / RC4 / EXPORT / DES /
anonymous). Also probes session resumption by doing the handshake
twice.

```bash
python -m cyberkit tlsenum example.com:443
python -m cyberkit tlsenum mail.example.com:993 --sni mail.example.com --skip-ciphers
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

### `passwordgen` — strong password / passphrase generator

CSPRNG-backed (`secrets.choice` / `secrets.randbelow`). Three modes:

* `rand` — random N-char password, guaranteed to contain at least one
  char from every selected class (lower/upper/digit/symbol) but with
  randomized positions so the result is still uniform. `--no-ambiguous`
  excludes visually-confusable chars (I l 1 O 0 …).
* `pass` — diceware-style passphrase from a built-in 250-word EFF-style
  list (or bring your own with `--wordlist`). Reports word-count entropy.
* `pin` — N-digit numeric PIN.

```bash
python -m cyberkit passwordgen rand -n 24 --no-ambiguous -c 5
python -m cyberkit passwordgen pass -w 6 --capitalize --add-digit
```

### `otp` — TOTP / HOTP

RFC 4226 (HOTP) + RFC 6238 (TOTP). Reads base32 secrets or full
`otpauth://...` URIs; supports SHA-1/256/512, custom digit length and
period, and verification with configurable time-skew window. Verified
against every Appendix-D vector of RFC 4226 and Appendix-B of RFC 6238.

```bash
python -m cyberkit otp gen JBSWY3DPEHPK3PXP
python -m cyberkit otp verify JBSWY3DPEHPK3PXP 123456 --window 2
python -m cyberkit otp parse "otpauth://totp/Acme:alice?secret=...&issuer=Acme"
```

### `crackzip` — ZipCrypto password cracker

Implements the ZipCrypto cipher (APPNOTE.TXT §6.1) directly: pre-feeds
the password into the three 32-bit keystream registers, runs them
through the 12-byte encryption header, and checks the last decrypted
byte against the entry's "check byte" (high byte of CRC, or of mod-time
for streaming entries). That's a tiny in-process test — 10⁵ candidates
per second on a single core, and we parallelize. Only on a match do
we actually decompress to verify (saves ~99.6% of the work). Supports
`--rules` mutation engine. (AES-256 zips would need a separate
implementation; stdlib `zipfile` can't decrypt them.)

```bash
python -m cyberkit crackzip secret.zip -w cyberkit/data/passwords-small.txt --rules
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

### `packetparse` — hex packet decoder

Decodes a hex string (raw, contiguous, or tcpdump `0x0000:` style) layer
by layer: Ethernet II → IPv4 / IPv6 → TCP / UDP / ICMP, with DNS as the
upper layer when the UDP src/dst port is 53. Defensive parsers — each
layer returns what it could decode even if higher layers are malformed.

```bash
python -m cyberkit packetparse --hex "aabbccddeeff112233445566 0800 4500003c..."
tcpdump -nn -x port 53 | python -m cyberkit packetparse --file -
```

### `pcap` — read libpcap capture files

Parses the classic libpcap savefile format from scratch (both byte
orders, both µs/ns timestamp resolutions, link types Ethernet / RAW IP
/ Null / Linux SLL). Each packet is decoded via `packetparse`, so you
get the same L2-L7 breakdown plus protocol histogram, top talkers, and
filtering by protocol / port.

```bash
python -m cyberkit pcap capture.pcap
python -m cyberkit pcap capture.pcap --proto TCP --port 443
python -m cyberkit pcap capture.pcap --json | jq .
```

### `entropy` — Shannon entropy with windowed view + magic-byte ID

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
  __main__.py        # dispatcher (25 subcommands)
  _common.py         # shared output helpers
  _md4.py            # pure-Python MD4 (NTLM; verified against RFC 1320)
  _dns.py            # pure-stdlib DNS resolver: UDP + TCP fallback on TC,
                     # TCP AXFR, RFC 1035 compression with loop protection
  portscan.py
  dnsenum.py
  mailcheck.py
  subtake.py
  cidr.py
  whois.py
  dirfuzz.py
  httpprobe.py
  cspaudit.py
  certinspect.py
  tlsenum.py
  hashid.py
  hashcrack.py
  crackzip.py
  pwdaudit.py
  passwordgen.py
  otp.py
  jwtinspect.py
  xorcrack.py
  baseconv.py
  secrets.py
  packetparse.py
  pcap.py
  entropy.py
  hexview.py
  data/
    passwords-small.txt
    dirs-small.txt
tests/
  test_*.py          # 206 unit tests; run with `python -m unittest`
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
