# Nexus Toolkit · v4.0

A unified **OSINT + offensive security** framework. It exposes one consistent
interface (`ScanResult`) over three tiers of tooling:

- **OSINT** — passive, public-source intelligence. No traffic to the target.
- **PENTEST** — active, *detection-only* probing (ports, misconfigs, fingerprints).
- **EXTERNAL** — thin wrappers around ~79 third-party security tools, including
  offensive ones (scanning, web fuzzing, Active Directory, cracking, C2).

> ### ⚠️ Authorisation & legal notice — read this first
>
> The **PENTEST** and **EXTERNAL** tiers send live traffic to, probe, and in the
> case of many external tools actively attack the target. They are lawful to use
> **only** against systems that you own, or for which you hold **explicit written
> authorisation** (a signed engagement / scope, a lab you control, or a sanctioned
> CTF). Tools such as Metasploit, msfvenom, impacket, netexec/CrackMapExec,
> BloodHound, hashcat and the wireless suite can cause damage and are illegal to
> point at third-party systems without permission in most jurisdictions.
>
> This project is a **convenience layer** — it does not bundle or implement any
> exploit or payload itself; it detects and shells out to tools you install
> separately. You are solely responsible for how you use it. No warranty.

```
   ███████╗ ███████╗ ██╗ ███╗   ██╗ ████████╗
   ██╔═══██╗██╔════╝ ██║ ████╗  ██║ ╚══██╔══╝
   ██║   ██║███████╗ ██║ ██╔██╗ ██║    ██║
   ██║   ██║╚════██║ ██║ ██║╚██╗██║    ██║
   ╚██████╔╝███████║ ██║ ██║ ╚████║    ██║
    ╚═════╝ ╚══════╝ ╚═╝ ╚═╝  ╚═══╝    ╚═╝
```

## Quick start

```bash
chmod +x install.sh && ./install.sh
./install.sh --with-tools                    # + Mr.Holmes, toutatis, zehef, DataProfiler

nexus                                        # launch TUI
nexus test@example.com                       # auto OSINT (target type detected)
nexus 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa      # auto crypto (BTC/ETH detected)
nexus -c osint -m breach test@example.com    # dedicated breach module
nexus -c osint -m social johndoe             # 30+ social platform links
nexus -c osint -m github torvalds            # GitHub OSINT
nexus -c osint -m discord @username          # Discord tag / username helper
nexus -c pentest -m ports example.com        # active port scan (authorised targets only)
nexus -c pentest -m js https://example.com   # JS endpoint + secret extraction
nexus -c pentest -m s3 mycompany             # S3/GCS/Azure bucket discovery
nexus -c external -m nmap scanme.nmap.org    # run an external tool wrapper
nexus --fullscan example.com --save-html     # all applicable modules, HTML report
nexus --list-modules                         # all modules + tool install status
nexus --check-tools                          # diagnose external tool detection
```

The command is installed as `nexus` (with `osint` kept as a backward-compatible
alias). Without a target it launches the TUI.

## Modules

### ◆ OSINT — passive, public sources only

No traffic reaches the subject; everything comes from public/third-party sources.

| Module     | Sources |
|------------|---------|
| `email`    | Gravatar · Holehe (120+ sites) · Hudson Rock · ProxyNova · EmailRep · **XposedOrNot** (risk score + breaches) · **StopForumSpam** · MX |
| `username` | WhatsMyName (600+ sites) |
| `domain`   | WHOIS · DNS · crt.sh · **CertSpotter** · OTX · Wayback · RapidDNS · urlscan |
| `ip`       | ip-api · ipwho.is · Shodan IDB · GreyNoise · OTX · **StopForumSpam** · rDNS · WHOIS |
| `phone`    | phonenumbers (offline, region-aware) · phone-number-api + lookup links |
| `web`      | HTTP headers · security grade · tech stack · SSL · Wayback · urlscan |
| `social`   | Link generator by target type: **username** → 65 platforms + 9 username-checkers (WhatsMyName · IDCrawl · KnowEm...); **email** → Epieos · IntelX · That'sThem · HIBP · DeHashed...; **phone** → 13 reverse-phone (Truecaller · Sync.me · NumLookup · ZLookup...); **name** → 18 people-search aggregators (IDCrawl · TruePeopleSearch · Radaris · ZabaSearch · FamilyTreeNow · PeekYou...) |
| `breach`   | Hudson Rock · ProxyNova · **XposedOrNot** · LeakCheck + manual links (HIBP · DeHashed · IntelX · BreachDirectory · Snusbase · PSBDMP) |
| `github`   | Profile · repos · gists · activity · commit emails (PushEvents) · SSH/GPG keys · orgs |
| `discord`  | Local validation of new usernames, legacy `name#1234` tags and user IDs · snowflake timestamp · public/manual lookup pivots |
| `image`    | Reverse-image (Google Lens · Yandex · Bing · TinEye · Baidu) · face search (PimEyes · FaceCheck.ID · Lenso) · forensics (FotoForensics · Metapicz · Jeffrey's EXIF) |
| `crypto`   | BTC (blockchain.info · mempool.space) + ETH (Ethplorer) on-chain balance/tx/tokens + explorer links (Blockchair · WalletExplorer · OXT · Etherscan) |

### ⚡ PENTEST — active, detection-only probing

These modules send live traffic to the target. They **detect** conditions
(open ports, misconfigurations, exposed endpoints) — they do **not** exploit them.

| Module          | What it does |
|-----------------|--------------|
| `ports`         | Async TCP port scan + banner grab (~50 top ports) |
| `subdomains`    | DNS bruteforce against built-in wordlist + takeover detection |
| `fingerprint`   | CMS / framework / WAF detection + favicon hash |
| `ssl`           | TLS handshake, cert inspection, chain verification |
| `dirs`          | Common path discovery with WAF / soft-404 filtering |
| `cors`          | Reflective / wildcard / null-origin ACAO detection |
| `open-redirect` | Common redirect parameter detection |
| `spring`        | Spring Boot Actuator misconfig detection |
| `js`            | JS bundle analyser: endpoints, secrets, source maps, dev comments |
| `s3`            | Cloud bucket discovery (AWS S3 · GCS · Azure) by keyword |

> **Only run PENTEST modules against hosts you own or are authorised to test.**

### ◊ EXTERNAL — third-party tool wrappers

Wrappers auto-detect whether each tool is installed and print install
instructions if not. They cover the full offensive spectrum — treat every one
of them as subject to the authorisation notice at the top of this file.

| Category | Tools |
|----------|-------|
| OSINT / social | sherlock, holehe, theHarvester, recon-ng, photon, finalrecon, arjun |
| Network scanning | nmap, masscan, naabu, puredns, dnsx, assetfinder, subfinder, amass, httpx, gospider, hakrawler, kiterunner |
| Web app testing | nuclei, ffuf, gobuster, feroxbuster, dalfox, sqlmap, gau, katana, waybackurls, nikto, wapiti, skipfish, wpscan, burpsuite, zaproxy, caido |
| Active Directory | crackmapexec, netexec, enum4linux(-ng), ldapdomaindump, kerbrute, bloodhound(-python), secretsdump, ntlmrelayx, psexec, wmiexec |
| Password cracking | hashcat, john, fcrackzip, crunch |
| Wireless / Bluetooth | aircrack-ng, airgeddon, wifite, bettercap, bluelog, blueranger |
| Cloud | prowler, pacu |
| Forensics | autopsy, volatility3, bulk_extractor, binwalk |
| Mobile | frida, objection, jadx, apktool, bytecode-viewer |
| Reverse engineering | ghidra, radare2, rizin, gdb |
| C2 / exploitation | metasploit, msfvenom, havoc |
| Data / misc | dataprofiler, mr.holmes, toutatis, zehef, wordlists (SecLists) |

Some helper tools are managed for you:

- **Mr.Holmes** is git-cloned into `~/.osint-toolkit/tools/`.
- **toutatis** / **zehef** are pip-installed (Instagram requires `IG_SESSION_ID`).
- **DataProfiler** is heavy (TensorFlow + scikit-learn) and gets its own venv at
  `~/.osint-toolkit/tools/dataprofiler/venv/`; use it to auto-detect PII
  (emails, phones, SSNs, cards, addresses, IPs) in local datasets.

Run `./install.sh --with-tools` to fetch these in one go. Everything else is
expected to already be on your PATH (this project targets pentest distros such
as Kali or Athena OS).

## CLI

```
nexus [target] [-c {osint,pentest,external}] [-m MODULE] [-d] [-f]
      [--timeout SECS] [--json] [--save-json] [--save-html]
      [-q] [--tui] [--list-modules] [--check-tools]
```

| Flag                | Effect                                                      |
|---------------------|-------------------------------------------------------------|
| `-c, --category`    | `osint` (default), `pentest`, or `external`                 |
| `-m, --module`      | Module / tool name (see `--list-modules`)                   |
| `-f, --fullscan`    | Run all applicable modules (scoped to `-c` if given)        |
| `-d, --deep`        | Chained OSINT scan with pivots (auto module only)           |
| `--timeout`         | Per-source timeout in seconds (default 30)                  |
| `--json`            | Raw JSON to stdout                                          |
| `--save-json`       | Persist JSON to `~/.osint-toolkit/output/`                  |
| `--save-html`       | Persist styled HTML report                                  |
| `--list-modules`    | Show available modules and tool install status, then exit   |
| `--check-tools`     | Diagnose external-tool detection (paths, methods) and exit  |

## TUI

Launch with `nexus` (no target). Three category tabs, each with grouped modules.

| Key       | Action                              |
|-----------|-------------------------------------|
| `Ctrl+T`  | Toggle between categories           |
| `Enter`   | Run selected module on the target   |
| `↑/↓`     | Pick module in sidebar              |
| `Ctrl+D`  | Toggle deep scan (OSINT auto)       |
| `Ctrl+S`  | Save current results as JSON        |
| `Ctrl+L`  | Clear screen                        |
| `Ctrl+C`  | Quit                                |

## Architecture

```
osint_toolkit/
├── cli.py            # arg parsing + Rich rendering
├── tui.py            # Textual interactive app
├── http.py           # shared async HTTP client
├── render.py         # Rich theming
├── models.py         # ScanResult / Finding dataclasses
├── correlate.py      # category dispatch + chained pivots
├── modules/          # ◆ OSINT (passive)
│   ├── email.py  username.py  domain.py  ip.py  phone.py
│   └── web.py  social.py  breach.py  github.py
├── pentest/          # ⚡ PENTEST (active, detection-only)
│   ├── ports.py  subdomains.py  fingerprint.py  ssl_audit.py
│   ├── dirs.py  web_audit.py  spring.py  js_recon.py  s3.py
│   └── wordlists.py
└── external/         # ◊ EXTERNAL (third-party tool wrappers)
    ├── base.py       # ExternalTool base class + runtime detection
    ├── __init__.py   # ALL_TOOLS registry (~79 entries)
    └── … one module per tool family
```

Every module exposes `async scan(target, *, timeout, ...) -> ScanResult`, so the
CLI, TUI, JSON export and correlator all consume the same shape. External tool
wrappers subclass `ExternalTool`; if a tool is missing they return install
guidance instead of failing.

## Requirements

- Python **3.10+** (developed/tested on 3.14).
- Python deps in `requirements.txt` (httpx, rich, textual, phonenumbers, holehe,
  aiohttp, beautifulsoup4, lxml, tldextract, python-whois, dnspython, cryptography).
- `dig` and `whois` on PATH improve DNS/WHOIS modules (degrade gracefully if absent).
- EXTERNAL tools are expected to be provided by your OS / package manager.
- `OSINT_DEFAULT_REGION` (ISO-3166 alpha-2, e.g. `FR`) sets the default country
  for national-format phone numbers (no `+`/country code). Defaults to `BE`.
- `GH_TOKEN` / `GITHUB_TOKEN` raise the GitHub OSINT rate limit (optional).

---

*For authorised security testing, research and education only. See the
authorisation notice at the top of this file.*
