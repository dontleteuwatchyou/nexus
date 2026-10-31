"""External tool wrappers — subprocess bridges to third-party OSINT tools.

Now supports 190+ external tools covering:
  • OSINT / Social (Sherlock, Holehe, TheHarvester, Recon-ng, Photon, FinalRecon, Arjun)
  • Network scanning (nmap, masscan, naabu, puredns, dnsx, assetfinder, subfinder, amass)
  • Network recon (massdns, dnsrecon, dnsenum, fierce, netdiscover, nbtscan, onesixtyone, braa, snmpcheck, fping, ike-scan)
  • Web app testing (httpx, nuclei, ffuf, gobuster, feroxbuster, dalfox, sqlmap, nikto, wapiti, skipfish, gospider, hakrawler, kiterunner, gau, katana, waybackurls, burpsuite, zaproxy, caido)
  • Web recon (wafw00f, whatweb, wfuzz, httrack, davtest, cadaver, commix, padbuster, slowhttptest, siege, joomscan, subjack, sublist3r, spiderfoot)
  • Passive recon / sniffing (p0f, sslyze, sslscan, responder, dsniff, tcpflow, tcpreplay, wireshark, tshark, zeek, mitm6, sniffjoke, suricata)
  • Brute force (hydra, medusa, ncrack, crowbar, patator)
  • Tunneling (chisel, iodine, proxychains, stunnel, ptunnel, udptunnel, sbd, dbd)
  • Active Directory (crackmapexec, netexec, bloodhound, bloodhound-python, enum4linux, enum4linux-ng, ldapdomaindump, kerbrute, impacket tools)
  • AD/Windows (chntpw, samdump2, smbmap)
  • Password cracking (hashcat, john, fcrackzip, crunch, wpscan, hashdeep, hashid, hashrat, ssdeep, rsmangler, pipal)
  • Wireless (aircrack-ng, airgeddon, wifite, bettercap, bluelog, blueranger, kismet, mdk3, cowpatty, bully, reaver, pixiewps, sparrow-wifi, spooftooph, rfcat)
  • Cloud (prowler, pacu)
  • Forensics (autopsy, volatility3, bulk_extractor, binwalk, scalpel, foremost, testdisk, pdfid, pdf-parser, reglookup, regripper, pasco, rifiuti)
  • OSINT extra (cewl, metagoofil, exiftool, maltego, dmitry, linkedin2username, pompem)
  • Post-exploit (evil-winrm, koadic, veil, shellter, weevely, webacoo)
  • VoIP / SIP (inviteflood, protos-sip, siparmyknife, sipcrack, sipp, sippts, sipsak, voiphopper)
  • Steganography / Malware (steghide, outguess, yara, capa)
  • System audit (chkrootkit, lynis, unhide, xspy, macchanger, socat, netmask, pwnat, yersinia)
  • Mobile (frida, objection, jadx, apktool, bytecode-viewer)
  • Reverse engineering (ghidra, radare2, rizin, gdb)
  • C2 / Exploitation (metasploit, msfvenom, havoc)

Tools are detected at runtime; if absent, the wrapper returns install
instructions instead of failing.
"""

# Active Directory
from .ad_enum import Enum4linux, Enum4linuxNG, Kerbrute, LdapDomainDump

# AD / Windows
from .ad_windows import Chntpw, Samdump2, Smbmap
from .amass import Amass

# Network scanning
from .assetfinder import Assetfinder
from .base import TOOLS_DIR, ExternalTool
from .bloodhound import BloodHound, BloodHoundPython
from .bluetooth import Bettercap, Bluelog, BlueRanger

# Brute force
from .bruteforce import Crowbar, Hydra, Medusa, Ncrack, Patator

# C2 / Exploitation
from .c2 import Havoc, Metasploit, MsfVenom

# Cloud
from .cloud import Pacu, Prowler

# Cloud extras
from .cloud_extra import Docker

# Extra cracking
from .crack_extra2 import (
    Crackle,
    FernWifiCracker,
    HashIdentifier,
    PoleNum,
    PskCrack,
    Sucrack,
    THCPptpBruter,
    THCSslDos,
)

# Password cracking
from .cracking import Crunch, Fcrackzip, Hashcat, John
from .cracking_extra import Hashdeep, Hashid, Hashrat, Pipal, Rsmangler, Ssdeep
from .dalfox import Dalfox
from .dataprofiler import DataProfiler
from .dnsx import DNSx, Puredns

# System enumeration
from .enumeration import LinEnum, LinuxSmartEnum, ShellNoob
from .feroxbuster import Feroxbuster

# Web app testing
from .ffuf import FFUF

# Forensics
from .forensics import Autopsy, Binwalk, BulkExtractor, Volatility3
from .forensics_extra import (
    Foremost,
    MacRobber,
    Magicrescue,
    Missidentify,
    Myrescue,
    Pasco,
    Pdfid,
    PdfParser,
    Recoverdm,
    Recoverjpeg,
    Reglookup,
    Regripper,
    Rifiuti,
    Safecopy,
    Scalpel,
    ScroungeNtfs,
    Testdisk,
    Undbx,
    Vinetto,
)
from .gau import GAU
from .gobuster import Gobuster
from .httpx import HTTPX
from .impacket import NTLMRelayX, Psexec, SecretsDump, Wmiexec
from .katana import Katana

# Malware / Steganography
from .malware_stegano import Capa, Outguess, Steghide, Yara

# Mobile
from .mobile import JADX, APKTool, BytecodeViewer, Frida, Objection

# External OSINT tool integrations
from .mrholmes import MrHolmes
from .naabu import Naabu
from .netexec import CrackMapExec, NetExec

# Network attack tools
from .network_attack import (
    Dhcpig,
    Emails2phonenumber,
    EnumerateIam,
    Iaxflood,
    Oscanner,
    S3scanner,
    Sctpscan,
    SmtpUserEnum,
    Unicornscan,
)

# Network extras (arp, dns tools, sniffers)
from .network_extra import (
    ArpScan,
    ArpSpoof,
    Dnschef,
    Dnsmap,
    DnsSpoof,
    Dnstracer,
    Dnswalk,
    FileSnarf,
    Hping3,
    MailSnarf,
    MsgSnarf,
    Ncat,
    Netcat,
    Nping,
    Sshmitm,
    Tcpdump,
    UrlSnarf,
    Webmitm,
    Whois,
)

# Network recon
from .network_recon import (
    Braa,
    Dnsenum,
    Dnsrecon,
    Fierce,
    Fping,
    Ikescan,
    Massdns,
    Nbtscan,
    Netdiscover,
    Onesixone,
    Snmpcheck,
)
from .nmap import Masscan, Nmap
from .nuclei import Nuclei

# OSINT extra
from .osint_extra import Cewl, Dmitry, Exiftool, Linkedin2username, Maltego, Metagoofil, Pompem

# OSINT / Social
from .osint_social import Arjun, FinalRecon, Holehe, Photon, ReconNg, Sherlock, TheHarvester

# System / Other
from .other import Chkrootkit, Lynis, Macchanger, Netmask, Pwnat, Socat, Unhide, Xspy, Yersinia

# Passive recon / sniffing
from .passive_recon import (
    Dsniff,
    Mitm6,
    P0f,
    Responder,
    Sniffjoke,
    Sslscan,
    Sslyze,
    Suricata,
    Tcpflow,
    Tcpreplay,
    Tshark,
    Wireshark,
    Zeek,
)

# Post-exploit
from .post_exploit import EvilWinRM, Koadic, Shellter, Veil, Webacoo, Weevely

# Reverse Engineering
from .reverse import GDB, Ghidra, Radare2, Rizin
from .spiders import GoSpider, Hakrawler, Kiterunner
from .sqlmap import SQLMap

# SSL/Crypto
from .ssl_crypto import Certipy, LigoloNgProxy, Ssldump, Sslh, Sslsniff, Sslsplit
from .subfinder import Subfinder
from .toutatis import Toutatis

# Tunneling
from .tunneling import Chisel, Dbd, Iodine, Proxychains, Ptunnel, Sbd, Stunnel, Udptunnel

# VoIP / SIP
from .voip import Inviteflood, ProtosSip, Siparmyknife, Sipcrack, Sipp, Sippts, Sipsak, Voiphopper

# VoIP extras
from .voip_extra import Svcrack, Svcrash, Svmap, Svreport, Svwar
from .waybackurls import WaybackURLs

# Web fuzzing extras
from .web_fuzz import Dirb, Dirsearch, Gitleaks, Trufflehog

# Web recon
from .web_recon import (
    WCVS,
    Cadaver,
    Commix,
    Davtest,
    Httrack,
    Joomscan,
    Padbuster,
    Raven,
    Siege,
    Slowhttptest,
    SpiderFoot,
    Subjack,
    Sublist3r,
    Wafw00f,
    WFuzz,
    WhatWeb,
)
from .webapp import ZAP, BurpSuite, Caido, Nikto, Skipfish, Wapiti

# Wireless / Bluetooth
from .wireless import AircrackNg, Airgeddon, Wifite
from .wireless_extra import (
    Bully,
    Cowpatty,
    Kismet,
    Mdk3,
    Pixiewps,
    Reaver,
    Rfcat,
    SparrowWifi,
    SpoofTooph,
)
from .wordlists import Wordlists
from .wpscan import WPScan
from .zehef import Zehef

ALL_TOOLS: list[type[ExternalTool]] = [
    # OSINT / Social (10)
    Sherlock, Holehe, TheHarvester, ReconNg, Photon, FinalRecon, Arjun,
    MrHolmes, Toutatis, Zehef,

    # Network scanning (11)
    Assetfinder, Subfinder, Amass, Nmap, Masscan,
    Naabu, HTTPX, Nuclei, DNSx, Puredns,

    # Network recon (11)
    Massdns, Dnsrecon, Dnsenum, Fierce, Netdiscover,
    Nbtscan, Onesixone, Braa, Snmpcheck, Fping, Ikescan,

    # Brute force (5)
    Hydra, Medusa, Ncrack, Crowbar, Patator,

    # Web app testing (15)
    FFUF, Gobuster, Feroxbuster, Dalfox, SQLMap,
    GAU, Katana, WaybackURLs, Nikto, Wapiti, Skipfish,
    BurpSuite, ZAP, Caido, WPScan,
    GoSpider, Hakrawler, Kiterunner,

    # Web recon (16)
    Wafw00f, WhatWeb, WFuzz, Httrack, Davtest, Cadaver,
    Commix, Padbuster, Slowhttptest, Siege, Joomscan,
    Subjack, Sublist3r, SpiderFoot, WCVS, Raven,

    # Passive recon / sniffing (13)
    P0f, Sslyze, Sslscan, Responder, Dsniff, Tcpflow,
    Tcpreplay, Wireshark, Tshark, Zeek, Mitm6, Sniffjoke,
    Suricata,

    # Tunneling (8)
    Chisel, Ptunnel, Udptunnel, Iodine, Proxychains,
    Stunnel, Sbd, Dbd,

    # Active Directory (10)
    Enum4linux, Enum4linuxNG, LdapDomainDump, Kerbrute,
    CrackMapExec, NetExec, BloodHound, BloodHoundPython,
    SecretsDump, NTLMRelayX, Psexec, Wmiexec,

    # Password cracking (10)
    Hashcat, John, Fcrackzip, Crunch,
    Hashdeep, Hashid, Hashrat, Ssdeep, Rsmangler, Pipal,

    # Wireless / Bluetooth (14)
    AircrackNg, Airgeddon, Wifite, Bluelog, BlueRanger,
    Kismet, Mdk3, Cowpatty, Bully, Reaver, Pixiewps,
    SparrowWifi, SpoofTooph, Rfcat,

    # Cloud (2)
    Prowler, Pacu,

    # Forensics (23)
    Autopsy, Volatility3, BulkExtractor, Binwalk,
    Scalpel, Foremost, Recoverdm, Recoverjpeg, ScroungeNtfs,
    Testdisk, Magicrescue, Safecopy, Myrescue, Pasco, Rifiuti,
    Reglookup, Regripper, Vinetto, Undbx, MacRobber, Missidentify,
    Pdfid, PdfParser,

    # Mobile (5)
    Frida, Objection, JADX, APKTool, BytecodeViewer,

    # Reverse Engineering (4)
    Ghidra, Radare2, Rizin, GDB,

    # C2 / Exploitation (3)
    Metasploit, MsfVenom, Havoc,

    # Wordlists
    Wordlists,

    # OSINT extra (7)
    Cewl, Metagoofil, Exiftool, Maltego, Dmitry,
    Linkedin2username, Pompem,

    # Post-exploit (6)
    EvilWinRM, Koadic, Veil, Shellter, Weevely, Webacoo,

    # AD / Windows (3)
    Chntpw, Samdump2, Smbmap,

    # VoIP / SIP (8)
    Inviteflood, ProtosSip, Siparmyknife, Sipcrack,
    Sipp, Sippts, Sipsak, Voiphopper,

    # System / Other (9)
    Chkrootkit, Lynis, Unhide, Xspy, Yersinia, Macchanger,
    Socat, Netmask, Pwnat,

    # Malware / Steganography (4)
    Steghide, Outguess, Yara, Capa,

    # Data analysis
    DataProfiler,

    # Network
    Bettercap,

    # Network extras (19)
    ArpScan, ArpSpoof, DnsSpoof, UrlSnarf, MailSnarf, FileSnarf,
    MsgSnarf, Webmitm, Sshmitm, Dnschef, Dnstracer, Dnsmap, Dnswalk,
    Ncat, Netcat, Nping, Hping3, Tcpdump, Whois,

    # Web fuzzing extras (4)
    Dirb, Dirsearch, Trufflehog, Gitleaks,

    # Extra cracking (8)
    Crackle, HashIdentifier, PskCrack, Sucrack,
    THCPptpBruter, THCSslDos, PoleNum, FernWifiCracker,

    # Network attack (9)
    Dhcpig, Iaxflood, Unicornscan, Oscanner, S3scanner,
    Sctpscan, SmtpUserEnum, Emails2phonenumber, EnumerateIam,

    # SSL/Crypto (6)
    Ssldump, Sslsniff, Sslsplit, Sslh, Certipy, LigoloNgProxy,

    # System enumeration (3)
    LinEnum, LinuxSmartEnum, ShellNoob,

    # VoIP extras (5)
    Svmap, Svwar, Svcrack, Svreport, Svcrash,

    # Cloud extras (1)
    Docker,
]


def available_tools() -> dict[str, bool]:
    return {t.name: t.is_installed() for t in ALL_TOOLS}


def find_tool(name: str) -> type[ExternalTool] | None:
    for t in ALL_TOOLS:
        if t.name.lower() == name.lower():
            return t
    return None


__all__ = [
    "ExternalTool", "TOOLS_DIR", "ALL_TOOLS",
    "available_tools", "find_tool",
]
