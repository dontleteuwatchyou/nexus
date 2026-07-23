"""Textual TUI — OSINT + Recon + External + Chat with tabbed sidebar."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.widgets import (Footer, Header, Input, ListItem, ListView, Static)

from .ai import NexusAI
from .correlate import (PENTEST_TARGET_TYPES, detect_target_type, scan_chained,
                        scan_full, scan_one)
from .external import find_tool
from .models import ScanResult

# Expressions pour detecter les cibles OSINT directement (fallback si l'IA refuse)
RE_EMAIL = re.compile(r'[\w\.-]+@[\w\.-]+\.\w{2,}')
RE_URL   = re.compile(r'https?://[^\s]+')
RE_IP    = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
RE_DOMAIN = re.compile(r'\b[\w\.-]+\.[a-z]{2,}\b')
RE_REFUSAL = re.compile(
    r"(je ne peux pas|je n'?ai pas|désolé|désolée|cannot|je ne suis pas|"
    r"doxxing|surveillance|refuse|éthique|illégal|illégal|"
    r"je ne peux t'aider|je ne peux pas vous aider"
    r"|I can't|I don't have|I cannot|I'm not able|je ne peux pas vous aider)", re.IGNORECASE)
RE_ACTIVE_INTENT = re.compile(
    r"\b(pentest|audit(?:er)?|scan actif|vuln(?:érabilité|erabilite)?|explo(?:it|iter))\b",
    re.IGNORECASE,
)
RE_AUTHORIZATION = re.compile(
    r"\b(j['’ ]autorise|autorisé|autorisee|m['’ ]appartient|mon (?:site|lab|réseau|reseau)|"
    r"permission|scope autorisé|scope autorise)\b",
    re.IGNORECASE,
)

# Reseaux sociaux connus pour extraire les usernames des URLs
SOCIAL_PATTERNS = {
    r'tiktok\.com/@(\w+)': 'username',
    r'snapchat\.com/add/(\w+)': 'username',
    r'snapchat\.com/@(\w+)': 'username',
    r'twitter\.com/(\w+)': 'username',
    r'x\.com/(\w+)': 'username',
    r'instagram\.com/(\w+)': 'username',
    r'facebook\.com/(\w+)': 'username',
    r'linkedin\.com/in/(\w+)': 'username',
    r'github\.com/(\w+)': 'username',
    r'reddit\.com/user/(\w+)': 'username',
    r'twitch\.tv/(\w+)': 'username',
    r'youtube\.com/@(\w+)': 'username',
    r'youtube\.com/c/(\w+)': 'username',
}

# Motifs pour detecter des pseudos/usernames dans le texte
RE_TAG = re.compile(r'tag\s+(?:est\s+)?(\w[\w.-]*)', re.IGNORECASE)
RE_APPELLE = re.compile(r'(?:surnom|pseudo|appel(?:le|lé|er|lait)?)[:\s]+(\w[\w.-]*)', re.IGNORECASE)

OUTPUT_DIR = Path.home() / ".osint-toolkit" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# Items per category. (key, label, description)
OSINT_ITEMS: list[tuple[str, str, str]] = [
    ("fullscan",  "✦  Full OSINT",  "All applicable OSINT modules"),
    ("auto",      "▸  Auto-scan",   "Detect target type, chain pivots"),
    ("email",     "  ✉  Email",     "name@domain.com"),
    ("username",  "  @  Username",  "johndoe"),
    ("domain",    "  ⌬  Domain",    "example.com"),
    ("ip",        "  ◉  IP addr",   "8.8.8.8"),
    ("phone",     "  ☏  Phone",     "+33612345678"),
    ("web",       "  ⌗  Web / URL", "https://example.com"),
    ("social",    "  ⌖  Social",    "johndoe (username)"),
    ("breach",    "  ⚠  Breach",    "name@domain.com / username"),
    ("github",    "  ⌬  GitHub",    "username"),
    ("discord",   "  ◈  Discord",   "@username / name#1234 / user ID"),
    ("image",     "  ▣  Image",     "https://…/photo.jpg (reverse image search)"),
    ("crypto",    "  ₿  Crypto",    "BTC / ETH address"),
]

PENTEST_ITEMS: list[tuple[str, str, str]] = [
    ("fullscan",      "⚡  Full Scan",      "All pentest — ports·subs·fp·ssl·dirs·cors·redirect·spring·js·s3"),
    ("ports",         "▸  Port scan",       "example.com / 192.168.1.1"),
    ("subdomains",    "▸  Subdomain enum",  "example.com"),
    ("fingerprint",   "▸  Fingerprint",     "https://example.com / example.com"),
    ("ssl",           "▸  SSL audit",       "example.com / 192.168.1.1"),
    ("dirs",          "▸  Directory enum",  "https://example.com"),
    ("cors",          "▸  CORS audit",      "https://example.com"),
    ("open-redirect", "▸  Open redirect",   "https://example.com"),
    ("spring",        "▸  Spring Actuator", "https://example.com"),
    ("js",            "▸  JS recon",        "https://example.com"),
    ("s3",            "▸  S3 / GCS / Azure","domain.com / companyname"),
]

# External tool groupings (sub-categories within the EXTERNAL tab)
EXTERNAL_CATEGORIES: dict[str, list[tuple[str, str, str]]] = {
    "OSINT/Social": [
        ("sherlock",      "◊  Sherlock",       "Username search (600+ sites)"),
        ("holehe",        "◊  Holehe",         "Email registration check (120+ sites)"),
        ("theharvester",  "◊  TheHarvester",   "Email · hosts · subdomains"),
        ("recon-ng",      "◊  Recon-ng",       "Modular OSINT framework"),
        ("photon",        "◊  Photon",         "Web crawler · URLs · emails"),
        ("finalrecon",    "◊  FinalRecon",     "Web recon · SSL · WAF · headers"),
        ("arjun",         "◊  Arjun",          "Parameter discovery"),
        ("cewl",          "◊  CeWL",           "Custom wordlist from URL"),
        ("metagoofil",    "◊  Metagoofil",     "Metadata extraction"),
        ("exiftool",      "◊  ExifTool",       "File metadata reader"),
        ("maltego",       "◊  Maltego",        "OSINT graph analysis (GUI)"),
        ("dmitry",        "◊  Dmitry",         "Deepmagic info gathering"),
        ("linkedin2username","◊  LI2User",     "LinkedIn username generator"),
        ("pompem",        "◊  Pompem",         "Exploit search tool"),
    ],
    "Network": [
        ("nmap",          "◊  Nmap",           "Port scan · version · scripts"),
        ("masscan",       "◊  Masscan",        "High-speed port scan (1-65535)"),
        ("naabu",         "◊  Naabu",          "Fast port scanner"),
        ("puredns",       "◊  Puredns",        "DNS resolver"),
        ("dnsx",          "◊  DNSx",           "DNS toolkit"),
        ("assetfinder",   "◊  Assetfinder",    "Subdomain discovery"),
        ("subfinder",     "◊  Subfinder",      "Passive subdomain enumeration"),
        ("amass",         "◊  Amass",          "OSINT subdomain enumeration"),
        ("httpx",         "◊  HTTPX",          "HTTP · TLS · CDN · tech detect"),
        ("gospider",      "◊  GoSpider",       "Web crawler · forms · JS"),
        ("hakrawler",     "◊  Hakrawler",      "Web crawler"),
        ("kiterunner",    "◊  Kiterunner",     "API route bruteforce"),
        ("massdns",       "◊  Massdns",        "DNS resolver bruteforce"),
        ("dnsrecon",      "◊  DNSRecon",       "DNS enumeration"),
        ("dnsenum",       "◊  DNSEnum",        "DNS enumeration"),
        ("fierce",        "◊  Fierce",         "DNS recon tool"),
        ("netdiscover",   "◊  Netdiscover",    "ARP scanner"),
        ("nbtscan",       "◊  Nbtscan",        "NetBIOS scanner"),
        ("onesixtyone",   "◊  Onesixyone",     "SNMP scanner"),
        ("braa",          "◊  Braa",           "SNMP bulk walker"),
        ("snmpcheck",     "◊  SNMPCheck",      "SNMP enumerator"),
        ("fping",         "◊  Fping",          "ICMP sweep"),
        ("ike-scan",      "◊  Ike-scan",       "VPN detection (ISAKMP)"),
        ("arp-scan",      "◊  ARP-scan",       "ARP scanner"),
        ("dnschef",       "◊  DNSchef",        "DNS proxy"),
        ("dnstracer",     "◊  DNStracer",      "DNS tracer"),
        ("dnsmap",        "◊  DNSmap",         "DNS mapping"),
        ("dnswalk",       "◊  DNSwalk",        "DNS walk"),
        ("nping",         "◊  Nping",          "Ping tool"),
        ("hping3",        "◊  Hping3",         "Packet crafting"),
        ("tcpdump",       "◊  Tcpdump",        "Packet capture"),
        ("whois",         "◊  Whois",          "Domain/IP WHOIS"),
        ("ncat",          "◊  Ncat",           "Netcat with SSL"),
        ("netcat",        "◊  Netcat",         "Traditional netcat"),
        ("unicornscan",   "◊  Unicornscan",    "Port scanner"),
        ("sctpscan",      "◊  SCTPscan",       "SCTP scanner"),
    ],
    "Web App Testing": [
        ("nuclei",        "◊  Nuclei",         "Template-based vulnerability scanner"),
        ("ffuf",          "◊  FFUF",           "Directory/file fuzzing"),
        ("gobuster",      "◊  Gobuster",       "Directory/DNS/Web brute-force"),
        ("feroxbuster",   "◊  Feroxbuster",    "Recursive directory discovery"),
        ("dalfox",        "◊  Dalfox",         "XSS scanner"),
        ("sqlmap",        "◊  SQLMap",         "Automatic SQL injection"),
        ("gau",           "◊  GAU",            "Historical URL discovery"),
        ("katana",        "◊  Katana",         "Next-gen web crawler"),
        ("waybackurls",   "◊  WaybackURLs",    "Wayback Machine URL discovery"),
        ("nikto",         "◊  Nikto",          "Web server scanner"),
        ("wapiti",        "◊  Wapiti",         "Web app vulnerability scanner"),
        ("skipfish",      "◊  Skipfish",       "Web app security scanner"),
        ("wpscan",        "◊  WPScan",         "WordPress vulnerability scanner"),
        ("burpsuite",     "◊  Burp Suite",     "Web proxy & scanner (GUI)"),
        ("zaproxy",       "◊  ZAP",            "Web app scanner (GUI)"),
        ("caido",         "◊  Caido",          "Web proxy (GUI)"),
        ("wafw00f",       "◊  Wafw00f",        "WAF detection"),
        ("whatweb",       "◊  WhatWeb",        "Web tech detection"),
        ("wfuzz",         "◊  WFuzz",          "Web fuzzer"),
        ("httrack",       "◊  HTTrack",        "Website copier"),
        ("davtest",       "◊  Davtest",        "WebDAV scanner"),
        ("cadaver",       "◊  Cadaver",        "WebDAV client"),
        ("commix",        "◊  Commix",         "Command injection detector"),
        ("padbuster",     "◊  Padbuster",      "Padding oracle attack"),
        ("slowhttptest",  "◊  Slowhttptest",   "DoS testing"),
        ("siege",         "◊  Siege",          "HTTP load testing"),
        ("joomscan",      "◊  Joomscan",       "Joomla scanner"),
        ("subjack",       "◊  Subjack",        "Subdomain takeover"),
        ("sublist3r",     "◊  Sublist3r",      "Subdomain enumeration"),
        ("spiderfoot",    "◊  SpiderFoot",     "OSINT automation"),
        ("dirb",          "◊  Dirb",           "URL brute-forcer"),
        ("dirsearch",     "◊  Dirsearch",      "Directory search"),
        ("trufflehog",    "◊  Trufflehog",     "Secret scanner"),
        ("gitleaks",      "◊  Gitleaks",       "Git secret scanner"),
        ("oscanner",      "◊  Oscanner",       "Oracle scanner"),
    ],
    "Web App Testing": [
        ("nuclei",        "◊  Nuclei",         "Template-based vulnerability scanner"),
        ("ffuf",          "◊  FFUF",           "Directory/file fuzzing"),
        ("gobuster",      "◊  Gobuster",       "Directory/DNS/Web brute-force"),
        ("feroxbuster",   "◊  Feroxbuster",    "Recursive directory discovery"),
        ("dalfox",        "◊  Dalfox",         "XSS scanner"),
        ("sqlmap",        "◊  SQLMap",         "Automatic SQL injection"),
        ("gau",           "◊  GAU",            "Historical URL discovery"),
        ("katana",        "◊  Katana",         "Next-gen web crawler"),
        ("waybackurls",   "◊  WaybackURLs",    "Wayback Machine URL discovery"),
        ("nikto",         "◊  Nikto",          "Web server scanner"),
        ("wapiti",        "◊  Wapiti",         "Web app vulnerability scanner"),
        ("skipfish",      "◊  Skipfish",       "Web app security scanner"),
        ("wpscan",        "◊  WPScan",         "WordPress vulnerability scanner"),
        ("burpsuite",     "◊  Burp Suite",     "Web proxy & scanner (GUI)"),
        ("zaproxy",       "◊  ZAP",            "Web app scanner (GUI)"),
        ("caido",         "◊  Caido",          "Web proxy (GUI)"),
        ("wafw00f",       "◊  Wafw00f",        "WAF detection"),
        ("whatweb",       "◊  WhatWeb",        "Web tech detection"),
        ("wfuzz",         "◊  WFuzz",          "Web fuzzer"),
        ("httrack",       "◊  HTTrack",        "Website copier"),
        ("davtest",       "◊  Davtest",        "WebDAV scanner"),
        ("cadaver",       "◊  Cadaver",        "WebDAV client"),
        ("commix",        "◊  Commix",         "Command injection detector"),
        ("padbuster",     "◊  Padbuster",      "Padding oracle attack"),
        ("slowhttptest",  "◊  Slowhttptest",   "DoS testing"),
        ("siege",         "◊  Siege",          "HTTP load testing"),
        ("joomscan",      "◊  Joomscan",       "Joomla scanner"),
        ("subjack",       "◊  Subjack",        "Subdomain takeover"),
        ("sublist3r",     "◊  Sublist3r",      "Subdomain enumeration"),
        ("spiderfoot",    "◊  SpiderFoot",     "OSINT automation"),
    ],
    "Passive Recon": [
        ("p0f",           "◊  p0f",            "Passive OS fingerprinting"),
        ("sslyze",        "◊  SSLyze",         "SSL/TLS config analyzer"),
        ("sslscan",       "◊  SSLScan",        "SSL/TLS scanner"),
        ("responder",     "◊  Responder",      "LLMNR/NBT-NS poisoner"),
        ("dsniff",        "◊  Dsniff",         "Network sniffer suite"),
        ("tcpflow",       "◊  Tcpflow",        "TCP flow recorder"),
        ("tcpreplay",     "◊  Tcpreplay",      "PCAP replay"),
        ("wireshark",     "◊  Wireshark",      "Packet analyzer (GUI)"),
        ("tshark",        "◊  TShark",         "CLI packet analyzer"),
        ("zeek",          "◊  Zeek",           "Network analysis engine"),
        ("mitm6",         "◊  mitm6",          "IPv6 MITM framework"),
        ("sniffjoke",     "◊  Sniffjoke",      "Traffic obfuscation"),
        ("suricata",      "◊  Suricata",       "IDS/IPS engine"),
        ("arpspoof",      "◊  ARPspoof",       "ARP spoofing"),
        ("dnsspoof",      "◊  DNSspoof",       "DNS spoofing"),
        ("urlsnarf",      "◊  URLsnarf",       "HTTP URL sniffer"),
        ("mailsnarf",     "◊  Mailsnarf",      "Email sniffer"),
        ("filesnarf",     "◊  Filesnarf",      "File sniffer"),
        ("msgsnarf",      "◊  Msgsnarf",       "Message sniffer"),
        ("webmitm",       "◊  Webmitm",        "Web MITM proxy"),
        ("sshmitm",       "◊  SSHmitm",        "SSH MITM proxy"),
        ("ssldump",       "◊  SSLDump",        "SSL traffic dump"),
        ("sslsniff",      "◊  SSLsniff",       "SSL MITM"),
        ("sslsplit",      "◊  SSLsplit",       "SSL MITM"),
        ("sslh",          "◊  SSLH",           "SSL/SSH multiplexer"),
    ],
    "Brute Force": [
        ("hydra",         "◊  Hydra",          "Network login cracker"),
        ("medusa",        "◊  Medusa",         "Parallel login brute-forcer"),
        ("ncrack",        "◊  Ncrack",         "High-speed network auth cracker"),
        ("crowbar",       "◊  Crowbar",        "Brute force tool (SSH/VPN)"),
        ("patator",       "◊  Patator",        "Multi-service brute forcer"),
        ("sucrack",       "◊  Sucrack",        "su brute-forcer"),
        ("thc-pptp-bruter","◊  THC-PPTP",      "PPTP VPN brute-forcer"),
        ("thc-ssl-dos",   "◊  THC-SSL-DoS",    "SSL DoS tool"),
    ],
    "Tunneling": [
        ("chisel",        "◊  Chisel",         "TCP/UDP tunnel over HTTP"),
        ("iodine",        "◊  Iodine",         "DNS tunnel"),
        ("proxychains",   "◊  Proxychains",    "Proxy chain tool"),
        ("stunnel",       "◊  Stunnel",        "SSL tunnel"),
        ("ptunnel",       "◊  Ptunnel",        "ICMP tunnel"),
        ("udptunnel",     "◊  UDPtunnel",      "UDP tunnel"),
        ("sbd",           "◊  Sbd",            "Backdoor tunnel"),
        ("dbd",           "◊  Dbd",            "Netcat backdoor"),
        ("ligolo-ng-proxy","◊  Ligolo-ng",     "Ligolo tunnel proxy"),
    ],
    "Attack / DoS": [
        ("dhcpig",        "◊  DHCPig",         "DHCP exhaustion attack"),
        ("iaxflood",      "◊  IAXflood",       "IAX flood (VoIP DoS)"),
        ("hping3",        "◊  Hping3",         "Packet crafting DoS"),
        ("yersinia",      "◊  Yersinia",       "Layer 2 attack tool"),
        ("crackle",       "◊  Crackle",        "BLE cracking"),
    ],
    "SSL/Crypto": [
        ("certipy",       "◊  Certipy",        "AD CS exploitation"),
        ("ssldump",       "◊  SSLDump",        "SSL traffic dump"),
        ("sslsniff",      "◊  SSLsniff",       "SSL MITM"),
        ("sslsplit",      "◊  SSLsplit",       "SSL MITM"),
        ("sslh",          "◊  SSLH",           "SSL/SSH multiplexer"),
        ("psk-crack",     "◊  PSK-crack",       "Pre-shared key cracker"),
    ],
    "Active Directory": [
        ("crackmapexec",  "◊  CrackMapExec",   "AD/SMB protocol toolkit"),
        ("netexec",       "◊  NetExec",        "CrackMapExec v2"),
        ("enum4linux",    "◊  Enum4linux",     "SMB enumeration"),
        ("enum4linux-ng", "◊  Enum4linux-ng",  "Advanced SMB enumeration"),
        ("ldapdomaindump","◊  LDAPDomainDump", "AD LDAP dump"),
        ("kerbrute",      "◊  Kerbrute",       "Kerberos user enumeration"),
        ("bloodhound",    "◊  BloodHound",     "AD graph analysis (GUI)"),
        ("bloodhound-python","◊  BloodHound-py","AD data collector"),
        ("secretsdump",   "◊  SecretsDump",    "DCSync hash extraction"),
        ("ntlmrelayx",    "◊  NTLMRelayX",     "NTLM relay attacks"),
        ("psexec",        "◊  PsExec",         "Remote command execution"),
        ("wmiexec",       "◊  WMIExec",        "WMI remote execution"),
        ("chntpw",        "◊  Chntpw",         "Windows password reset"),
        ("samdump2",      "◊  Samdump2",       "SAM hash dumper"),
        ("smbmap",        "◊  Smbmap",         "SMB share enumerator"),
    ],
    "Wireless": [
        ("aircrack-ng",   "◊  Aircrack-ng",    "WEP/WPA key cracking"),
        ("airgeddon",     "◊  Airgeddon",      "WiFi multi-tool (GUI)"),
        ("wifite",        "◊  Wifite",         "Automated WiFi audit"),
        ("bettercap",     "◊  Bettercap",      "MITM framework"),
        ("bluelog",       "◊  Bluelog",        "Bluetooth scanner"),
        ("blueranger",    "◊  BlueRanger",     "Bluetooth range detection"),
        ("kismet",        "◊  Kismet",         "Wireless sniffer (GUI)"),
        ("mdk3",          "◊  MDK3",           "WiFi DoS tool"),
        ("cowpatty",      "◊  Cowpatty",       "WPA2-PSK cracking"),
        ("bully",         "◊  Bully",          "WPS brute force"),
        ("reaver",        "◊  Reaver",         "WPS attack tool"),
        ("pixiewps",      "◊  Pixiewps",       "WPS offline crack"),
        ("sparrow-wifi",  "◊  SparrowWifi",    "WiFi analyzer (GUI)"),
        ("spooftooph",    "◊  Spooftooph",     "Bluetooth spoofing"),
        ("rfcat",         "◊  Rfcat",          "RF hacking toolkit"),
    ],
    "Password Cracking": [
        ("hashcat",       "◊  Hashcat",        "GPU password cracking"),
        ("john",          "◊  John",           "John the Ripper"),
        ("fcrackzip",     "◊  Fcrackzip",      "ZIP password cracking"),
        ("crunch",        "◊  Crunch",         "Wordlist generator"),
        ("hashdeep",      "◊  Hashdeep",       "Hash computation"),
        ("hashid",        "◊  Hashid",         "Hash type identifier"),
        ("hashrat",       "◊  Hashrat",        "Hash computation tool"),
        ("ssdeep",        "◊  Ssdeep",         "Fuzzy hashing"),
        ("rsmangler",     "◊  Rsmangler",      "Wordlist mangler"),
        ("pipal",         "◊  Pipal",          "Password analyzer"),
        ("hash-identifier","◊  Hash-ID",       "Hash type identification"),
        ("polenum",       "◊  PoleNum",        "Password policy enumeration"),
        ("fern-wifi-cracker","◊  Fern-WiFi",   "WiFi cracking (GUI)"),
    ],
    "Cloud": [
        ("prowler",       "◊  Prowler",        "AWS/Azure/GCP security audit"),
        ("pacu",          "◊  Pacu",           "AWS exploitation framework"),
        ("s3scanner",     "◊  S3scanner",      "S3 bucket enumeration"),
        ("enumerate-iam", "◊  Enum-IAM",       "AWS IAM enumeration"),
        ("docker",        "◊  Docker",         "Container engine audit"),
    ],
    "Enumeration": [
        ("linenum",       "◊  LinEnum",        "Linux enumeration"),
        ("linux-smart-enumeration","◊  LSE",   "Smart Linux enumeration"),
        ("shellnoob",     "◊  ShellNoob",      "Shellcode tools"),
        ("smtp-user-enum","◊  SMTP-Enum",      "SMTP user enumeration"),
        ("emails2phonenumber","◊  E2P",        "Email to phone number"),
        ("oscanner",      "◊  Oscanner",       "Oracle scanner"),
    ],
    "Cloud": [
        ("prowler",       "◊  Prowler",        "AWS/Azure/GCP security audit"),
        ("pacu",          "◊  Pacu",           "AWS exploitation framework"),
    ],
    "Forensics": [
        ("autopsy",       "◊  Autopsy",        "Disk forensics (GUI)"),
        ("volatility3",   "◊  Volatility3",    "Memory forensics"),
        ("bulk_extractor","◊  Bulk Extractor", "Digital media feature extraction"),
        ("binwalk",       "◊  Binwalk",        "Firmware analysis"),
        ("scalpel",       "◊  Scalpel",        "File carver"),
        ("foremost",      "◊  Foremost",       "File carver"),
        ("testdisk",      "◊  Testdisk",       "Disk recovery"),
        ("pdfid",         "◊  PDFiD",          "PDF analysis"),
        ("pdf-parser",    "◊  PDF-Parser",     "PDF parser"),
        ("reglookup",     "◊  Reglookup",      "Registry parser"),
        ("regripper",     "◊  Regripper",      "Registry analysis"),
        ("pasco",         "◊  Pasco",          "IE cache parser"),
        ("rifiuti",       "◊  Rifiuti",        "Recycle bin parser"),
    ],
    "Post-Exploit": [
        ("evil-winrm",    "◊  Evil-WinRM",     "WinRM shell"),
        ("koadic",        "◊  Koadic",         "Post-exploitation tool"),
        ("veil",          "◊  Veil",           "Payload generator"),
        ("shellter",      "◊  Shellter",       "Shellcode injector"),
        ("weevely",       "◊  Weevely",        "Web shell"),
        ("webacoo",       "◊  Webacoo",        "Web backdoor"),
    ],
    "VoIP/SIP": [
        ("inviteflood",   "◊  Inviteflood",    "SIP INVITE flood"),
        ("protos-sip",    "◊  Protos-SIP",     "SIP protocol testing"),
        ("siparmyknife",  "◊  SIPArmyKnife",   "SIP testing"),
        ("sipcrack",      "◊  SIPcrack",       "SIP password cracker"),
        ("sipp",          "◊  SIPp",           "SIP traffic generator"),
        ("sippts",        "◊  SIPpTS",         "SIP security testing"),
        ("sipsak",        "◊  Sipsak",         "SIP test tool"),
        ("voiphopper",    "◊  VoIPHopper",     "VLAN hopping"),
        ("sipvicious-svmap","◊  Svmap",        "SIP scanner"),
        ("sipvicious-svwar","◊  Svwar",        "SIP war dialer"),
        ("sipvicious-svcrack","◊  Svcrack",    "SIP password cracker"),
        ("sipvicious-svreport","◊  Svreport",  "SIP report"),
        ("sipvicious-svcrash","◊  Svcrash",    "SIP crash tool"),
    ],
    "System Audit": [
        ("chkrootkit",    "◊  Chkrootkit",     "Rootkit detector"),
        ("lynis",         "◊  Lynis",          "Security auditing"),
        ("unhide",        "◊  Unhide",         "Hidden process detector"),
        ("xspy",          "◊  Xspy",           "X11 keylogger"),
        ("yersinia",      "◊  Yersinia",       "Layer 2 attack tool"),
        ("macchanger",    "◊  Macchanger",     "MAC address changer"),
        ("socat",         "◊  Socat",          "Multipurpose relay"),
        ("netmask",       "◊  Netmask",        "Network mask calculator"),
        ("pwnat",         "◊  Pwnat",          "NAT traversal"),
    ],
    "Malware/Stegano": [
        ("steghide",      "◊  Steghide",       "Image steganography"),
        ("outguess",      "◊  Outguess",       "Steganography tool"),
        ("yara",          "◊  Yara",           "Malware pattern matcher"),
        ("capa",          "◊  Capa",           "Malware capability analyzer"),
    ],
    "Mobile": [
        ("frida",         "◊  Frida",          "Dynamic instrumentation"),
        ("objection",     "◊  Objection",      "Mobile app exploration"),
        ("jadx",          "◊  JADX",           "APK/DEX decompiler"),
        ("apktool",       "◊  APKTool",        "APK reverse engineering"),
        ("bytecode-viewer","◊  Bytecode Viewer","Bytecode decompiler (GUI)"),
    ],
    "Reverse Eng": [
        ("ghidra",        "◊  Ghidra",         "RE suite (GUI)"),
        ("radare2",       "◊  Radare2",        "Reverse engineering framework"),
        ("rizin",         "◊  Rizin",          "Radare2 fork"),
        ("gdb",           "◊  GDB",            "GNU debugger"),
    ],
    "C2/Exploit": [
        ("metasploit",    "◊  Metasploit",     "Exploitation framework"),
        ("msfvenom",      "◊  MsfVenom",       "Payload generator"),
        ("havoc",         "◊  Havoc",          "C2 framework (GUI)"),
    ],
    "Data Tools": [
        ("wordlists",     "◊  Wordlists",      "Browse/search SecLists wordlists"),
        ("dataprofiler",  "◊  DataProfiler",   "Dataset PII detection"),
        ("mr.holmes",     "◊  Mr.Holmes",      "Multi-purpose OSINT"),
        ("toutatis",      "◊  Toutatis",       "Instagram OSINT"),
        ("zehef",         "◊  Zehef",          "Email account/breach check"),
    ],
}


def _external_items() -> list[tuple[str, str, str, str]]:
    """Return list of (category, key, label, desc) for all external tools."""
    items = []
    for cat_name, tool_list in EXTERNAL_CATEGORIES.items():
        for key, label, desc in tool_list:
            tool = find_tool(key)
            installed = ""
            if tool:
                installed = " ✓" if tool.is_installed() else " ✗"
            items.append((cat_name, key, f"{label}{installed}", desc))
    return items


CSS = """
Screen { background: #0a0a0a; }

#header-bar {
    height: 3; padding: 0 2; background: #141414;
    color: #fb923c; border-bottom: solid #2a2a2a;
}

#target-input {
    margin: 1 2; border: round #404040; background: #141414;
    color: #f5f5f5;
}
#target-input:focus { border: round #fb923c; }

#main-container { height: 1fr; }

#sidebar {
    width: 36; background: #141414;
    border-right: solid #2a2a2a;
    padding: 0;
}

#tabs {
    height: 3;
    background: #0a0a0a;
    border-bottom: solid #2a2a2a;
    padding: 0;
}

.tab {
    width: 1fr;
    height: 3;
    content-align: center middle;
    background: #141414;
    color: #737373;
    text-style: bold;
    border-right: solid #2a2a2a;
}
.tab:hover { background: #1c1c1c; color: #d4d4d4; }

.tab-active-osint {
    background: #1f1207;
    color: #fb923c;
    border-bottom: thick #fb923c;
}
.tab-active-pentest {
    background: #1f0808;
    color: #ef4444;
    border-bottom: thick #dc2626;
}
.tab-active-external {
    background: #1a1207;
    color: #fdba74;
    border-bottom: thick #f59e0b;
}
.tab-active-chat {
    background: #0f1a0f;
    color: #4ade80;
    border-bottom: thick #22c55e;
}

#list-container {
    padding: 1;
    height: 1fr;
}

ListView {
    background: transparent;
    border: none;
    height: auto;
}

.hidden { display: none; }

ListItem {
    background: transparent;
    padding: 0 1;
    height: 3;
}
ListItem:hover { background: #1c1c1c; }

ListItem.--highlight { background: #1f1f1f; }
#osint-list ListItem.--highlight { background: #1f1207; color: #fb923c; }
#pentest-list ListItem.--highlight { background: #2a0a0a; color: #f87171; }
#external-list ListItem.--highlight { background: #1a1207; color: #fdba74; }

#mode-hint {
    margin: 1 1 0 1;
    padding: 1;
    color: #525252;
}

#results-container { background: #0a0a0a; padding: 1 2; }
#results { background: #0a0a0a; color: #e5e5e5; }

#chat-container {
    height: 1fr; background: #0a0a0a;
    padding: 0 1;
}
#chat-scroll {
    height: 1fr;
    min-height: 5;
    overflow-y: auto;
}
#chat-messages-wrapper {
    height: auto; background: #0a0a0a;
    margin: 0 0 1 0;
}
#chat-messages-wrapper > Static {
    margin: 0 0 1 0;
}
#chat-input {
    dock: bottom; margin: 0 0 1 0;
    border: round #404040; background: #141414; color: #f5f5f5;
    min-height: 3;
}
#chat-input:focus { border: round #fb923c; }

#chat-header { height: 3; margin: 1 0 0 1; }

Footer { background: #141414; color: #737373; }
Footer > .footer--key {
    background: #7f1d1d; color: #fef2f2; text-style: bold;
}
"""


SEVERITY_STYLES = {
    "found": "#fbbf24",
    "warn":  "#fb923c",
    "error": "#ef4444",
    "info":  "#a3a3a3",
}


class ModuleRow(ListItem):
    def __init__(self, category: str, key: str, label: str, desc: str,
                 sub_category: str = "") -> None:
        super().__init__()
        self.category = category
        self.key_id = key
        self.label_text = label
        self.desc_text = desc
        self.sub_category = sub_category

    def compose(self) -> ComposeResult:
        if self.category == "osint":
            color = "#f5f5f5"
        elif self.category == "pentest":
            color = "#fca5a5"
        else:
            color = "#fdba74"
        label = self.label_text
        if self.sub_category:
            label = f"[dim #525252]{self.sub_category}[/] {label}"
        yield Static(
            f"[bold {color}]{label}[/]\n"
            f"[dim italic #737373]{self.desc_text}[/]"
        )


class Tab(Static):
    def __init__(self, category: str, label: str) -> None:
        super().__init__(label, id=f"tab-{category}")
        self.category = category
        self.add_class("tab")


class OsintApp(App):
    """OSINT + Recon + External tools — Textual TUI."""

    CSS = CSS

    BINDINGS = [
        Binding("ctrl+c", "quit",       "Quit",          show=True, priority=True),
        Binding("ctrl+s", "save_json",  "JSON",          show=True),
        Binding("ctrl+p", "save_html",  "HTML",          show=True),
        Binding("ctrl+y", "copy",       "Copy",          show=True),
        Binding("ctrl+l", "clear",      "Clear",         show=True),
        Binding("ctrl+d", "deep_scan",  "Pivot+",        show=True),
        Binding("ctrl+t", "switch_tab", "Switch mode",   show=True, priority=True),
        Binding("ctrl+o", "set_osint",  "OSINT",         show=False, priority=True),
        Binding("ctrl+r", "set_pentest",  "PENTEST",     show=False, priority=True),
        Binding("ctrl+e", "set_external", "EXTERNAL",    show=False, priority=True),
        Binding("ctrl+h", "set_chat",   "Chat",          show=False, priority=True),
    ]

    TITLE     = "Nexus Toolkit"
    SUB_TITLE = "v4.0 · OSINT mode"

    active_category: reactive[str] = reactive("osint")
    last_results:    reactive[dict] = reactive({})
    last_target:     reactive[str]  = reactive("")
    deep_mode:       reactive[bool] = reactive(False)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Input(placeholder="  Target: email · username · domain · IP · phone · URL",
                     id="target-input")
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                with Horizontal(id="tabs"):
                    yield Tab("osint", "◆  OSINT")
                    yield Tab("pentest", "⚡  RECON")
                    yield Tab("external", "◊  EXT")
                    yield Tab("chat", "✉  CHAT")
                with Vertical(id="list-container"):
                    yield ListView(
                        *[ModuleRow("osint", k, l, d) for k, l, d in OSINT_ITEMS],
                        id="osint-list",
                    )
                    yield ListView(
                        *[ModuleRow("pentest", k, l, d) for k, l, d in PENTEST_ITEMS],
                        id="pentest-list",
                        classes="hidden",
                    )
                    yield ListView(
                        *[ModuleRow("external", k, l, d, sub_category=cat)
                          for cat, k, l, d in _external_items()],
                        id="external-list",
                        classes="hidden",
                    )
                    yield Static(
                        "[dim]Ctrl+T[/]  cycle tabs\n"
                        "[dim]Ctrl+O/R/E/H[/]  direct\n"
                        "[dim]Enter[/]   run module\n"
                        "[dim]Ctrl+Y[/]  copy results\n"
                        "[dim]Ctrl+S[/]  save JSON\n"
                        "[dim]Ctrl+D[/]  deep (OSINT)\n"
                        "\n"
                        "[dim italic]Shift+select bypasses\n"
                        "TUI for partial copy[/]",
                        id="mode-hint",
                    )
            with ScrollableContainer(id="results-container"):
                yield Static(self._splash_text(), id="results")
            with Vertical(id="chat-container", classes="hidden"):
                yield Static("[bold #f59e0b]✉  Chat — Assistant IA OSINT/Pentest[/]", id="chat-header")
                with ScrollableContainer(id="chat-scroll"):
                    yield Static("", id="chat-messages-wrapper")
                yield Input(placeholder="  Demande moi n'importe quoi (OSINT, pentest, analyse...)",
                             id="chat-input")
        yield Footer()

    # ── lifecycle ──

    def on_mount(self) -> None:
        self._apply_active_tab()
        self.query_one("#osint-list", ListView).index = 0
        self.query_one("#target-input", Input).focus()

    # ── tab switching ──

    def _apply_active_tab(self) -> None:
        osint_list   = self.query_one("#osint-list", ListView)
        recon_list   = self.query_one("#pentest-list", ListView)
        ext_list     = self.query_one("#external-list", ListView)
        tab_osint    = self.query_one("#tab-osint", Tab)
        tab_recon    = self.query_one("#tab-pentest", Tab)
        tab_ext      = self.query_one("#tab-external", Tab)
        tab_chat     = self.query_one("#tab-chat", Tab)
        target_input = self.query_one("#target-input", Input)
        results_ct   = self.query_one("#results-container")
        chat_ct      = self.query_one("#chat-container")

        # Reset
        for t in (tab_osint, tab_recon, tab_ext, tab_chat):
            t.remove_class("tab-active-osint")
            t.remove_class("tab-active-pentest")
            t.remove_class("tab-active-external")
            t.remove_class("tab-active-chat")
        for l in (osint_list, recon_list, ext_list):
            l.add_class("hidden")
        results_ct.remove_class("hidden")
        chat_ct.add_class("hidden")
        target_input.remove_class("hidden")

        if self.active_category == "osint":
            tab_osint.add_class("tab-active-osint")
            osint_list.remove_class("hidden")
            target_input.placeholder = "  ↑↓ Select a module → format shown here"
            self.sub_title = "v4.0 · OSINT mode"
        elif self.active_category == "pentest":
            tab_recon.add_class("tab-active-pentest")
            recon_list.remove_class("hidden")
            target_input.placeholder = "  ↑↓ Select a module → format shown here"
            self.sub_title = "v4.0 · PENTEST mode"
        elif self.active_category == "external":
            tab_ext.add_class("tab-active-external")
            ext_list.remove_class("hidden")
            target_input.placeholder = "  ↑↓ Select a module → format shown here"
            self.sub_title = "v4.0 · EXTERNAL tools"
        else:  # chat
            tab_chat.add_class("tab-active-chat")
            results_ct.add_class("hidden")
            target_input.add_class("hidden")
            chat_ct.remove_class("hidden")
            self.sub_title = "v4.0 · Chat mode"
            self.query_one("#chat-input", Input).focus()

    def watch_active_category(self, _: str) -> None:
        try:
            self._apply_active_tab()
        except Exception:
            pass

    def action_switch_tab(self) -> None:
        order = ["osint", "pentest", "external", "chat"]
        idx = order.index(self.active_category)
        self.active_category = order[(idx + 1) % len(order)]

    def action_set_osint(self) -> None:    self.active_category = "osint"
    def action_set_pentest(self) -> None:  self.active_category = "pentest"
    def action_set_external(self) -> None: self.active_category = "external"
    def action_set_chat(self) -> None:     self.active_category = "chat"

    OSINT_HINTS = {
        "fullscan": "email / username / domain / IP / phone / URL",
        "auto":     "email / username / domain / IP / phone / URL",
        "email":    "name@domain.com",
        "username": "johndoe",
        "domain":   "example.com",
        "ip":       "8.8.8.8",
        "phone":    "+33612345678",
        "web":      "https://example.com",
        "social":   "johndoe",
        "breach":   "name@domain.com / username",
        "github":   "username",
        "discord":  "@username / name#1234 / user ID",
        "image":    "https://…/photo.jpg",
        "crypto":   "BTC / ETH address",
    }

    PENTEST_HINTS = {
        "fullscan":      "domain / IP / URL",
        "ports":         "example.com / 192.168.1.1",
        "subdomains":    "example.com",
        "fingerprint":   "https://example.com / example.com",
        "ssl":           "example.com / 192.168.1.1",
        "dirs":          "https://example.com",
        "cors":          "https://example.com",
        "open-redirect": "https://example.com",
        "spring":        "https://example.com",
        "js":            "https://example.com",
        "s3":            "domain.com / companyname",
    }

    def _update_placeholder(self, key_id: str, category: str) -> None:
        hints = self.OSINT_HINTS if category == "osint" else self.PENTEST_HINTS
        hint = hints.get(key_id, "target")
        self.query_one("#target-input", Input).placeholder = f"  Format: {hint}"

    @on(ListView.Highlighted, "#osint-list")
    def on_osint_highlight(self, event) -> None:
        if self.active_category != "osint":
            return
        item = event.item
        if isinstance(item, ModuleRow):
            self._update_placeholder(item.key_id, "osint")

    @on(ListView.Highlighted, "#pentest-list")
    def on_pentest_highlight(self, event) -> None:
        if self.active_category != "pentest":
            return
        item = event.item
        if isinstance(item, ModuleRow):
            self._update_placeholder(item.key_id, "pentest")

    @on(ListView.Highlighted, "#external-list")
    def on_external_highlight(self, event) -> None:
        if self.active_category != "external":
            return
        item = event.item
        if not isinstance(item, ModuleRow):
            return
        tool = find_tool(item.key_id)
        if tool is None:
            return
        kinds = ", ".join(sorted(tool.accepted_kinds)) or "(any)"
        installed = "✓" if tool.is_installed() else "✗"
        self.query_one("#target-input", Input).placeholder = (
            f"  [{installed} {tool.name}] Target: {kinds}"
        )

    @on(events.Click, ".tab")
    def on_tab_click(self, event: events.Click) -> None:
        node = event.widget
        while node is not None and not isinstance(node, Tab):
            node = node.parent
        if isinstance(node, Tab):
            self.active_category = node.category

    # ── input ──

    def _current_list(self) -> ListView:
        return self.query_one(
            {"osint":    "#osint-list",
             "pentest":    "#pentest-list",
             "external": "#external-list"}[self.active_category],
            ListView,
        )

    def _current_module(self) -> str | None:
        lv = self._current_list()
        item = lv.highlighted_child
        if isinstance(item, ModuleRow):
            return item.key_id
        return None

    @on(Input.Submitted, "#target-input")
    def on_submit(self, event: Input.Submitted) -> None:
        target = event.value.strip()
        if not target:
            return
        module = self._current_module()
        if not module:
            self.notify("Pick a module first (↑/↓ in sidebar)", severity="warning")
            return
        self.last_target = target
        self.run_scan(target, self.active_category, module, deep=self.deep_mode)

    # ── chat ──

    CHAT_HELP = (
        "[bold #f59e0b]Nexus Chat — Assistant OSINT[/]\n\n"
        "Parle naturellement, les cibles sont extraites automatiquement.\n"
        "Les reponses sont courtes (15 lignes max).\n\n"
        "[bold #4ade80]Exemples :[/]\n"
        "  [dim]>[/] scan email test@example.com\n"
        "  [dim]>[/] trouve infos sur https://tiktok.com/@user\n"
        "  [dim]>[/] check les pseudos kaz et nokeh\n\n"
        "[#737373]Si l'IA refuse, le scan direct prend le relais.[/]"
    )

    def _chat_render(self, messages: list[dict]) -> str:
        if not messages:
            if not hasattr(self, "_nexus_ai"):
                self._nexus_ai = NexusAI()
            return (
                self.CHAT_HELP
                + f"\n\n[#737373]Profil local : "
                + escape(self._nexus_ai.runtime_summary)
                + "[/]\n"
            )
        out = []
        for m in messages:
            role = m["role"]
            content = escape(m["content"].strip())
            if role == "user":
                out.append(f"[bold #fbbf24]▸ Toi[/]\n[#e5e5e5]{content}[/]")
            elif role == "assistant":
                out.append(f"[bold #4ade80]▸ Assistant[/]\n[#d4d4d4]{content}[/]")
            else:
                out.append(f"[bold #737373]▸ Système[/]\n[#a3a3a3]{content}[/]")
            out.append("[#2a2a2a]─[/]" * 40)
        return "\n".join(out) + "\n"

    async def _run_nexus_ai(self, msg: str) -> str:
        if not hasattr(self, "_nexus_ai"):
            self._nexus_ai = NexusAI()
        return await self._nexus_ai.answer(msg)

    def _detect_targets(self, msg: str) -> list[tuple[str, str]]:
        """Detect OSINT targets in a message. Returns [(target, type), ...]."""
        targets = []
        seen = set()
        # Extraire pseudos depuis "appelé/appelle/appeler/pseudo: XXX"
        for m in RE_APPELLE.finditer(msg):
            t = m.group(1).strip()
            if t not in seen and len(t) > 2:
                targets.append((t, "username"))
                seen.add(t)
        # Extraire depuis "son tag est nokeh"
        for m in RE_TAG.finditer(msg):
            t = m.group(1).strip()
            if t not in seen and len(t) > 1:
                targets.append((t, "username"))
                seen.add(t)
        # Extraire les usernames des URLs reseaux sociaux
        for pattern, typ in SOCIAL_PATTERNS.items():
            for m in re.finditer(pattern, msg, re.IGNORECASE):
                t = m.group(1).lower()
                if t not in seen:
                    targets.append((t, "username"))
                    seen.add(t)
        # Cibles classiques (email, ip, url, domain)
        for m in RE_EMAIL.finditer(msg):
            t = m.group(0).lower()
            if t not in seen:
                targets.append((t, "email"))
                seen.add(t)
        for m in RE_IP.finditer(msg):
            t = m.group(0)
            if t not in seen:
                targets.append((t, "ip"))
                seen.add(t)
        for m in RE_URL.finditer(msg):
            t = m.group(0)
            if t not in seen:
                targets.append((t, "url"))
                seen.add(t)
        for m in RE_DOMAIN.finditer(msg):
            t = m.group(0).lower()
            if t not in seen and not t.startswith("http"):
                targets.append((t, "domain"))
                seen.add(t)
        return targets

    def _scan_to_chat(self, results: dict[str, ScanResult]) -> str:
        out = []
        for key, r in results.items():
            parts = key.split(":", 2)
            cat, mod, val = (parts + [""] * 3)[:3] if len(parts) >= 2 else ("", "", "")
            n_total = len(r.findings)
            n_found = len(r.by_severity("found"))

            badge = f"[bold #4ade80]{n_found} trouve[/]" if n_found else ""
            if r.errors and n_total > 0:
                badge += f" [#ef4444]{len(r.errors)} err[/]"

            by_src = {}
            for f in r.findings:
                by_src.setdefault(f.source, []).append(f)

            lines = []
            for src, findings in list(by_src.items())[:5]:
                labels = ", ".join(
                    f"{escape(f.label)}: {escape(str(f.value)[:50])}"
                    for f in findings[:2]
                )
                if len(findings) > 2:
                    labels += f" [+{len(findings)-2}]"
                lines.append(f"  [#fdba74]•[/] [dim]{escape(src)}:[/] {labels}")
            if len(by_src) > 5:
                lines.append(f"  [dim]... + {len(by_src)-5} sources[/]")

            out.append(
                f"[bold #f59e0b]◆ {escape(mod.upper())}[/] [#a3a3a3]{escape(val)}[/]"
                f" [#737373]· {n_total} resultats[/] {badge}\n"
                + "\n".join(lines)
            )
        return "\n".join(out)

    @work(exclusive=True)
    async def run_chat(self, msg: str) -> None:
        wrapper = self.query_one("#chat-messages-wrapper", Static)
        scroll_ct = self.query_one("#chat-scroll")
        if not hasattr(self, "_chat_history"):
            self._chat_history = []

        self._chat_history.append({"role": "user", "content": msg})

        targets = self._detect_targets(msg)
        if RE_AUTHORIZATION.search(msg):
            self._pentest_authorized = True
        SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        start = __import__("time").time()
        last_status = ""
        def _set_status(line: str) -> None:
            nonlocal last_status
            if line.startswith("$ "):
                last_status = f"[#f59e0b]$ {line[2:]}[/]"
            elif line.startswith(">"):
                last_status = f"[#737373]{line}[/]"
            elif last_status and not line.startswith("$ "):
                last_status += f"\n[#a3a3a3]{line}[/]"
            else:
                last_status = f"[#a3a3a3]{line}[/]"

        def _tick():
            s = SPINNER[(int(__import__("time").time() - start) // 2) % len(SPINNER)]
            elapsed = int(__import__("time").time() - start)
            wrapper.update(
                self._chat_render(self._chat_history)
                + f"\n[#4ade80]{s} Scan en cours... ({elapsed}s)[/]\n"
                + last_status
            )
            try:
                scroll_ct.scroll_end(animate=False)
            except Exception:
                pass
        timer = self.set_interval(1, _tick)

        if targets:
            target, _ = targets[0]
            _set_status(f"> {target}")
            wants_active = bool(RE_ACTIVE_INTENT.search(msg))
            active_allowed = wants_active and getattr(
                self, "_pentest_authorized", False
            )
            sem = asyncio.Semaphore(4)

            async def _run(cat: str, mod: str) -> tuple[str, ScanResult]:
                async with sem:
                    key = f"{cat}:{mod}:{target}"
                    try:
                        r = await asyncio.wait_for(
                            scan_one(target, category=cat, module=mod, timeout=25.0),
                            timeout=30.0,
                        )
                    except (asyncio.TimeoutError, Exception):
                        r = ScanResult(target=target, module=mod)
                    _set_status(f"> [done] {mod}")
                    return key, r

            ttype = targets[0][1]
            if ttype == "email":
                selected_osint = {"email", "breach"}
            elif ttype == "username":
                selected_osint = {"username", "social", "breach"}
            elif ttype == "ip":
                selected_osint = {"ip", "breach"}
            elif ttype == "domain":
                selected_osint = {"domain", "url", "breach"}
            elif ttype == "url":
                selected_osint = {"url", "domain", "breach"}
            else:
                selected_osint = {"domain", "url", "breach"}

            pentest_mods = {"fingerprint", "ssl", "headers", "whois", "js",
                            "dirs", "spring", "cors", "dns-sec", "graphql"}

            tasks = [asyncio.create_task(_run("osint", m)) for m in selected_osint]
            if active_allowed:
                tasks += [
                    asyncio.create_task(_run("pentest", m))
                    for m in pentest_mods
                ]

            all_results = {}
            for fut in asyncio.as_completed(tasks):
                try:
                    key, res = await fut
                except Exception:
                    continue
                if res.findings:
                    all_results[key] = res

            timer.stop()
            elapsed = int(__import__("time").time() - start)
            if all_results:
                response = (
                    f"[bold #4ade80]Scan ({elapsed}s)[/]\n"
                    f"{self._scan_to_chat(all_results)}"
                )
            else:
                response = "[dim]No results[/dim]"
            if wants_active and not active_allowed:
                response += (
                    "\n\n[#f59e0b]Pentest actif prêt.[/] Confirme une seule fois "
                    "que la cible est autorisée (ex. « j’autorise ce lab »), puis "
                    "relance la demande. La confirmation restera valable pendant "
                    "cette session."
                )
        else:
            response = await self._run_nexus_ai(msg)
            timer.stop()

            # Tronquer les reponses trop longues ou bruites
            RESP_MAX_LINES = 200
            RESP_MAX_CHARS = 15000
            lines = response.split("\n")
            html_lines = sum(1 for l in lines if "<" in l and ">" in l)
            if html_lines > len(lines) * 0.3:
                response = "[dim]Reponse brute ignoree (HTML). L'essentiel est dans le fichier JSON.[/]"

            if len(lines) > RESP_MAX_LINES or len(response) > RESP_MAX_CHARS:
                lines = response.split("\n")
                clean = [l for l in lines if not any(
                    tag in l.lower() for tag in [
                        "<!doctype", "<html", "curl -s", "just a moment",
                        "cloudflare", "<script", "cf_chl_opt", "challenge-platform",
                        "window._cf", "content-security-policy", "nonce="])]
                if clean:
                    lines = clean
                response = "\n".join(lines[:RESP_MAX_LINES])
                if len(lines) > RESP_MAX_LINES:
                    response += (
                        f"\n\n[#737373]... tronque ({len(lines)} lignes)[/]"
                    )

            is_refusal = bool(RE_REFUSAL.search(response[:200]))
            if is_refusal:
                response = "[dim]Assistant non disponible[/dim]"

        self._chat_history.append({"role": "assistant", "content": response})
        wrapper.update(self._chat_render(self._chat_history))
        try:
            scroll_ct.scroll_end(animate=False)
        except Exception:
            pass

    @on(Input.Submitted, "#chat-input")
    def on_chat_submit(self, event: Input.Submitted) -> None:
        msg = event.value.strip()
        if not msg:
            return
        event.input.value = ""
        self.run_chat(msg)

    # ── scan execution ──

    @work(exclusive=True)
    async def run_scan(self, target: str, category: str, module: str, *,
                        deep: bool = False) -> None:
        results_widget = self.query_one("#results", Static)

        SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        start = __import__("time").time()
        elapsed = 0

        def _tick() -> None:
            nonlocal elapsed
            elapsed = int(__import__("time").time() - start)
            s = SPINNER[(elapsed // 2) % len(SPINNER)]
            status = (
                f"[#fb923c bold]  {s} Scanning...  {elapsed}s[/]\n"
                f"  [dim]target:[/]   [#f5f5f5 bold]{target}[/]\n"
                f"  [dim]category:[/] [#f59e0b]{category.upper()}[/]  "
                f"[dim]module:[/] [#fdba74]{module}[/]"
            )
            if module == "fullscan":
                status += f"\n  [dim]Running all applicable modules...[/]"
            try:
                results_widget.update(status)
            except Exception:
                pass

        # Start a recurring timer (cancelled when scan completes)
        timer = self.set_interval(1, _tick)

        def _progress(key: str, _result, done: int, total: int):
            s = SPINNER[(int(__import__("time").time() - start) // 2) % len(SPINNER)]
            status = (
                f"[#fb923c bold]  {s} Scanning...  [{done}/{total}] {key}[/]\n"
                f"  [dim]target:[/]   [#f5f5f5 bold]{target}[/]\n"
                f"  [dim]category:[/] [#f59e0b]{category.upper()}[/]\n"
                f"  [dim]# modules:[/] [#fbbf24]{done}[/][dim]/{total} completed[/]\n"
            )
            try:
                results_widget.update(status)
            except Exception:
                pass

        try:
            if module == "fullscan":
                results = await scan_full(target, timeout=30.0, category=category,
                                          progress_cb=_progress)
            elif category == "osint":
                if module == "auto":
                    if deep:
                        results = await scan_chained(target, depth=1)
                    else:
                        detected = detect_target_type(target)
                        if detected == "unknown":
                            timer.stop()
                            results_widget.update(
                                f"[#ef4444 bold]✗ Could not detect target type for:[/] {target}"
                            )
                            return
                        res = await scan_one(target, category="osint", module=detected)
                        results = {f"osint:{detected}:{target}": res}
                else:
                    res = await scan_one(target, category="osint", module=module)
                    results = {f"osint:{module}:{target}": res}
            elif category == "pentest":
                tt = detect_target_type(target)
                allowed = PENTEST_TARGET_TYPES.get(module, set())
                if allowed and tt not in allowed:
                    timer.stop()
                    results_widget.update(
                        f"[#ef4444 bold]✗ {module}[/] expects "
                        f"[#fb923c]{', '.join(sorted(allowed))}[/], got "
                        f"[#737373]{tt}[/]"
                    )
                    return
                res = await scan_one(target, category="pentest", module=module)
                results = {f"pentest:{module}:{target}": res}
            else:  # external
                res = await scan_one(target, category="external", module=module,
                                      kind=detect_target_type(target))
                results = {f"external:{module}:{target}": res}
        except Exception as e:
            timer.stop()
            results_widget.update(f"[#ef4444 bold]✗ Scan crashed:[/] {e}")
            return

        timer.stop()
        self.last_results = results
        results_widget.update(self._render_results(results))

    # ── rendering ──

    def _splash_text(self) -> str:
        return """[#fb923c bold]

   ███████╗ ███████╗ ██╗ ███╗   ██╗ ████████╗
   ██╔═══██╗██╔════╝ ██║ ████╗  ██║ ╚══██╔══╝
   ██║   ██║███████╗ ██║ ██╔██╗ ██║    ██║
   ██║   ██║╚════██║ ██║ ██║╚██╗██║    ██║
   ╚██████╔╝███████║ ██║ ██║ ╚████║    ██║
    ╚═════╝ ╚══════╝ ╚═╝ ╚═╝  ╚═══╝    ╚═╝
[/]
            [#fdba74 bold]toolkit v4.0[/] [dim]· OSINT + active pentest + external[/]

      [#fbbf24]100% open sources[/]   [dim]·[/]   [#a3a3a3]no API keys required[/]

   [dim]Switch with[/]  [#f5f5f5 bold]Ctrl+T[/]  [dim](cycle) /[/]  [#f5f5f5 bold]Ctrl+O[/]  [dim](OSINT) /[/]  [#f5f5f5 bold]Ctrl+R[/]  [dim](RECON) /[/]  [#f5f5f5 bold]Ctrl+E[/]  [dim](EXT)[/]

    [#fb923c bold]◆ OSINT[/]    [dim]passive public sources (10 modules)[/]
    [#dc2626 bold]⚡ PENTEST[/]   [dim]active probes — authorized hosts only (10 modules)[/]
    [    #f59e0b bold]◊ EXTERNAL[/] [dim]260+ tools — nmap · nuclei · hydra · certipy · dirb · tcpdump · yara...[/]"""

    def _scanning_text(self, target: str, category: str, module: str, deep: bool) -> str:
        deep_str = " [#fb923c](deep)[/]" if deep else ""
        cat_color = {"osint": "#fb923c", "pentest": "#dc2626",
                     "external": "#f59e0b"}.get(category, "#a3a3a3")
        return f"""
[#fb923c bold]  ⟳ Scanning...[/]

  [dim]target:  [/] [#f5f5f5 bold]{target}[/]
  [dim]category:[/] [{cat_color} bold]{category.upper()}[/]
  [dim]module:  [/] [#fdba74 bold]{module}[/]{deep_str}

  [dim]Running concurrent probes. May take 5–90 seconds depending on
  which sources respond.[/]
"""

    def _render_results(self, results: dict[str, ScanResult]) -> str:
        out = []
        for key, result in results.items():
            parts = key.split(":", 2)
            if len(parts) == 3:
                cat, mod, val = parts
            else:
                cat, mod, val = "osint", parts[0], parts[1]
            cat_color = {"osint": "#fb923c", "pentest": "#dc2626",
                          "external": "#f59e0b"}.get(cat, "#fb923c")
            out.append(f"\n[{cat_color} bold]▸  {cat.upper()} · {mod.upper()}[/]  [#f5f5f5]{escape(val)}[/]")
            out.append(f"[#2a2a2a]{'─' * 70}[/]\n")
            out.append(self._render_one(result))
            out.append("")
        out.append("\n[dim]Ctrl+P = HTML[/dim]  [dim]Ctrl+S = JSON[/dim]  [dim]Ctrl+Y = Copy[/dim]")
        return "\n".join(out)

    def _render_one(self, result: ScanResult) -> str:
        if not result.findings and not result.errors:
            return "  [dim italic]No data found.[/]\n"

        by_src: dict[str, list] = {}
        for f in result.findings:
            by_src.setdefault(f.source, []).append(f)

        lines = []
        for src, findings in by_src.items():
            lines.append(f"  [#fdba74 bold]◆ {escape(src)}[/]")
            for f in findings:
                color = SEVERITY_STYLES.get(f.severity, "#e5e5e5")
                value = str(f.value)
                if len(value) > 110:
                    value = value[:107] + "..."
                value = escape(value)
                label = escape(str(f.label))
                lines.append(
                    f"    [#a3a3a3]{label:<24}[/] [{color}]{value}[/]"
                )
            lines.append("")

        n_found = len(result.by_severity("found"))
        n_warn  = len(result.by_severity("warn"))
        n_info  = len(result.by_severity("info"))
        n_err   = len(result.errors)
        lines.append(
            f"  [dim]──── [/]"
            f"[#fbbf24]● {n_found} hits[/]  "
            f"[#fb923c]● {n_warn} flags[/]  "
            f"[#a3a3a3]● {n_info} info[/]  "
            f"[#ef4444]● {n_err} errors[/]"
        )
        if result.errors:
            for e in result.errors:
                lines.append(f"  [#ef4444]✗[/] [dim]{e}[/]")
        return "\n".join(lines)

    # ── actions ──

    def action_save_json(self) -> None:
        if not self.last_results:
            self.notify("Nothing to save yet.", severity="warning")
            return
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        target_safe = "".join(c if c.isalnum() else "_" for c in self.last_target)[:40]
        path = OUTPUT_DIR / f"scan_{target_safe}_{ts}.json"
        data = {k: r.as_dict() for k, r in self.last_results.items()}
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        self.notify(f"Saved to {path}", severity="information", title="Export")

    def action_save_html(self) -> None:
        if not self.last_results:
            self.notify("Nothing to save yet.", severity="warning")
            return
        from .cli import _save_html
        target = self.last_target or "unknown"
        path = _save_html(self.last_results, target)
        self.notify(f"HTML → {path}", severity="information", title="Export")

    def _strip_tags(self, text: str) -> str:
        return re.sub(r"\[/?[^\]]*\]", "", text)

    def action_copy(self) -> None:
        """Copy current results or chat response to system clipboard (OSC 52)."""
        if self.active_category == "chat" and hasattr(self, "_chat_history") and self._chat_history:
            last = self._chat_history[-1]
            if last["role"] == "assistant":
                text = self._strip_tags(last["content"])
                try:
                    self.copy_to_clipboard(text)
                    self.notify(f"Dernière réponse copiée ({len(text):,} chars)",
                                 severity="information", title="Chat")
                    return
                except Exception as e:
                    self.notify(f"Copy failed: {e}", severity="error")
                    return
            else:
                full = self._strip_tags("\n".join(m["content"] for m in self._chat_history))
                try:
                    self.copy_to_clipboard(full)
                    self.notify(f"Historique complet copié ({len(full):,} chars)",
                                 severity="information", title="Chat")
                    return
                except Exception as e:
                    self.notify(f"Copy failed: {e}", severity="error")
                    return

        if not self.last_results:
            self.notify("Nothing to copy yet.", severity="warning")
            return
        tag_re = re.compile(r"\[/?[^\]]*\]")
        lines = []
        for key, result in self.last_results.items():
            parts = key.split(":", 2)
            cat, mod, val = (parts + [""] * 3)[:3] if len(parts) >= 2 else ("", "", "")
            lines.append(f"▸ {cat.upper()} · {mod.upper()}  {val}")
            lines.append("─" * 70)
            by_src: dict[str, list] = {}
            for f in result.findings:
                by_src.setdefault(f.source, []).append(f)
            for src, findings in by_src.items():
                lines.append(f"  ◆ {src}")
                for f in findings:
                    value = str(f.value)
                    if len(value) > 200:
                        value = value[:197] + "..."
                    lines.append(f"    {f.label:<24}  {value}")
                lines.append("")
            if result.errors:
                lines.append("  errors:")
                for e in result.errors:
                    lines.append(f"    ✗ {e}")
            lines.append("")
        text = tag_re.sub("", "\n".join(lines))
        try:
            self.copy_to_clipboard(text)
            n = sum(len(r.findings) for r in self.last_results.values())
            self.notify(f"Copied {n} findings ({len(text):,} chars) to clipboard",
                         severity="information", title="Clipboard")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def action_clear(self) -> None:
        self.query_one("#results", Static).update(self._splash_text())
        self.query_one("#target-input", Input).value = ""
        self.last_results = {}

    def action_deep_scan(self) -> None:
        if self.active_category != "osint":
            self.notify("Deep mode only applies to OSINT", severity="warning")
            return
        self.deep_mode = not self.deep_mode
        state = "[#fb923c]ON[/]" if self.deep_mode else "[dim]OFF[/]"
        self.notify(f"Deep scan (correlation pivots): {state}")


def run() -> None:
    OsintApp().run()


if __name__ == "__main__":
    run()
