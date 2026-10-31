# OSINT Toolkit v4 — System Configuration

This file documents the osint-toolkit-v4 project for AI agents.

## Project Structure

```
/home/seclists/DISK2 (JMS DELETE)/Perso/Project/osint-toolkit-v4/
├── install.sh                          # Installer (uses pkexec, not sudo)
├── requirements.txt                    # Python dependencies
├── README.md                           # Full documentation
├── AGENTS.md                           # This file
└── osint_toolkit/
    ├── __init__.py                     # Version
    ├── __main__.py                     # `python -m osint_toolkit` entry
    ├── cli.py                          # CLI argparser + rendering
    ├── tui.py                          # Textual TUI (3 categories with sub-groups)
    ├── correlate.py                    # Scan dispatch + module catalog
    ├── http.py                         # Async HTTP client
    ├── models.py                       # ScanResult / Finding dataclasses
    ├── render.py                       # Rich theming
    ├── modules/                        # OSINT (passive public-source)
    │   ├── email.py, username.py, domain.py, ip.py, phone.py
    │   ├── web.py, social.py, breach.py, github.py, image.py, crypto.py
    ├── recon/                          # RECON (active probes)
    │   ├── ports.py, subdomains.py, fingerprint.py, ssl_audit.py
    │   ├── dirs.py, web_audit.py, spring.py, js_recon.py, s3.py
    │   └── wordlists.py
    └── external/                       # 80+ external tool wrappers
        ├── __init__.py                 # ALL_TOOLS registry (79 entries)
        ├── base.py                     # ExternalTool base class
        ├── osint_social.py             # Sherlock, Holehe, TheHarvester, Recon-ng, Photon, FinalRecon, Arjun
        ├── assetfinder.py, subfinder.py, amass.py, nmap.py (Nmap + Masscan)
        ├── naabu.py, httpx.py, nuclei.py
        ├── ffuf.py, gobuster.py, feroxbuster.py, dalfox.py, sqlmap.py
        ├── gau.py, katana.py, waybackurls.py, dnsx.py (DNSx + Puredns)
        ├── webapp.py (Nikto, Wapiti, Skipfish, BurpSuite, ZAP, Caido)
        ├── wpscan.py, spiders.py (GoSpider, Hakrawler, Kiterunner)
        ├── ad_enum.py (Enum4linux, Enum4linuxNG, LdapDomainDump, Kerbrute)
        ├── netexec.py (CrackMapExec, NetExec)
        ├── bloodhound.py (BloodHound, BloodHoundPython)
        ├── impacket.py (SecretsDump, NTLMRelayX, Psexec, Wmiexec)
        ├── cracking.py (Hashcat, John, Fcrackzip, Crunch)
        ├── wireless.py (AircrackNg, Airgeddon, Wifite)
        ├── bluetooth.py (Bettercap, Bluelog, BlueRanger)
        ├── cloud.py (Prowler, Pacu)
        ├── forensics.py (Autopsy, Volatility3, BulkExtractor, Binwalk)
        ├── mobile.py (Frida, Objection, JADX, APKTool, BytecodeViewer)
        ├── reverse.py (Ghidra, Radare2, Rizin, GDB)
        ├── c2.py (Metasploit, MsfVenom, Havoc)
        ├── wordlists.py (SecLists manager)
        ├── mrholmes.py, toutatis.py, zehef.py, dataprofiler.py
```

## Key Architecture

- **3 scan categories**: `osint` (passive), `recon` (active probes), `external` (tool wrappers)
- Every module returns `ScanResult(findings=[], errors=[], raw={})`
- External tools are auto-detected at runtime via `ExternalTool.install_status()`
- If not installed, they return install instructions instead of failing
- TUI has sub-categories in the External tab for easy navigation

## System Details

- **OS**: Athena OS (Arch-based penetration testing distribution)
- **Python**: 3.14 (from `/usr/sbin/python3`)
- **Shell**: zsh
- **Package manager**: pacman (pkexec preferred over sudo for privilege escalation)
- **Wordlists**: `/usr/share/seclists/` (SecLists)
- **Go runtime**: Available (`/usr/sbin/go`)
- **Privilege escalation**: Use `pkexec` (not `sudo`)

## Available External Tools (80 total, ~74 installed)

### OSINT/Social (7)
sherlock, holehe, theHarvester, recon-ng, photon, finalrecon, arjun

### Network Scanning (11)
nmap, masscan, naabu, puredns, dnsx, assetfinder, subfinder, amass, httpx, gospider, hakrawler, kiterunner

### Web App Testing (16)
nuclei, ffuf, gobuster, feroxbuster, dalfox, sqlmap, gau, katana, waybackurls, nikto, wapiti, skipfish, wpscan, burpsuite, zaproxy, caido

### Active Directory (12)
crackmapexec, netexec, enum4linux, enum4linux-ng, ldapdomaindump, kerbrute, bloodhound, bloodhound-python, secretsdump, ntlmrelayx, psexec, wmiexec

### Password Cracking (4)
hashcat, john, fcrackzip, crunch

### Wireless/Bluetooth (6)
aircrack-ng, airgeddon, wifite, bettercap, bluelog, blueranger

### Cloud (2)
prowler, pacu

### Forensics (4)
autopsy, volatility3, bulk_extractor, binwalk

### Mobile (5)
frida, objection, jadx, apktool, bytecode-viewer

### Reverse Engineering (4)
ghidra, radare2, rizin, gdb

### C2/Exploitation (3)
metasploit, msfvenom, havoc

### Data Tools (5)
dataprofiler, mr.holmes, toutatis, zehef, wordlists

## Usage

```bash
# TUI mode
python3 -m osint_toolkit
osint

# CLI mode - OSINT
osint test@example.com                        # auto-detect
osint -m domain example.com                    # specific module
osint -c recon -m ports example.com            # recon module

# CLI mode - External tools
osint -c external -m nmap scanme.nmap.org
osint -c external -m nuclei example.com
osint -c external -m crackmapexec 192.168.1.100
osint -c external -m sherlock johndoe

# Export
osint -c recon -m fingerprint example.com --save-json --save-html

# List modules
osint --list-modules
osint --check-tools
```

## Python Dependencies (requirements.txt)
- httpx, rich, textual (core)
- phonenumbers, holehe (OSINT)
- aiohttp, beautifulsoup4, lxml (web scraping)
- tldextract, python-whois, dnspython (DNS/WHOIS)
- cryptography (SSL/TLS)
