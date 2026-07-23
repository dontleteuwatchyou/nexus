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

from .base import ExternalTool, TOOLS_DIR
from .wordlists import Wordlists

# OSINT / Social
from .osint_social import Sherlock, Holehe, TheHarvester, ReconNg, Photon, FinalRecon, Arjun

# Network scanning
from .assetfinder import Assetfinder
from .subfinder import Subfinder
from .amass import Amass
from .nmap import Nmap, Masscan
from .naabu import Naabu
from .httpx import HTTPX
from .nuclei import Nuclei
from .dnsx import DNSx, Puredns

# Network recon
from .network_recon import Massdns, Dnsrecon, Dnsenum, Fierce, Netdiscover, Nbtscan, Onesixone, Braa, Snmpcheck, Fping, Ikescan

# Brute force
from .bruteforce import Hydra, Medusa, Ncrack, Crowbar, Patator

# Web app testing
from .ffuf import FFUF
from .gobuster import Gobuster
from .feroxbuster import Feroxbuster
from .dalfox import Dalfox
from .sqlmap import SQLMap
from .gau import GAU
from .katana import Katana
from .waybackurls import WaybackURLs
from .webapp import Nikto, Wapiti, Skipfish, BurpSuite, ZAP, Caido
from .spiders import GoSpider, Hakrawler, Kiterunner

# Web recon
from .web_recon import Wafw00f, WhatWeb, WFuzz, Httrack, Davtest, Cadaver, Commix, Padbuster, Slowhttptest, Siege, Joomscan, Subjack, Sublist3r, SpiderFoot, WCVS, Raven

# Passive recon / sniffing
from .passive_recon import P0f, Sslyze, Sslscan, Responder, Dsniff, Tcpflow, Tcpreplay, Wireshark, Tshark, Zeek, Mitm6, Sniffjoke, Suricata

# Tunneling
from .tunneling import Chisel, Ptunnel, Udptunnel, Iodine, Proxychains, Stunnel, Sbd, Dbd

# Active Directory
from .ad_enum import Enum4linux, Enum4linuxNG, LdapDomainDump, Kerbrute
from .netexec import CrackMapExec, NetExec
from .bloodhound import BloodHound, BloodHoundPython
from .impacket import SecretsDump, NTLMRelayX, Psexec, Wmiexec

# Password cracking
from .cracking import Hashcat, John, Fcrackzip, Crunch
from .cracking_extra import Hashdeep, Hashid, Hashrat, Ssdeep, Rsmangler, Pipal
from .wpscan import WPScan

# Wireless / Bluetooth
from .wireless import AircrackNg, Airgeddon, Wifite
from .wireless_extra import Kismet, Mdk3, Cowpatty, Bully, Reaver, Pixiewps, SparrowWifi, SpoofTooph, Rfcat
from .bluetooth import Bettercap, Bluelog, BlueRanger

# Cloud
from .cloud import Prowler, Pacu

# Forensics
from .forensics import Autopsy, Volatility3, BulkExtractor, Binwalk
from .forensics_extra import Scalpel, Foremost, Recoverdm, Recoverjpeg, ScroungeNtfs, Testdisk, Magicrescue, Safecopy, Myrescue, Pasco, Rifiuti, Reglookup, Regripper, Vinetto, Undbx, MacRobber, Missidentify, Pdfid, PdfParser

# Mobile
from .mobile import Frida, Objection, JADX, APKTool, BytecodeViewer

# Reverse Engineering
from .reverse import Ghidra, Radare2, Rizin, GDB

# C2 / Exploitation
from .c2 import Metasploit, MsfVenom, Havoc

# External OSINT tool integrations
from .mrholmes import MrHolmes
from .toutatis import Toutatis
from .dataprofiler import DataProfiler
from .zehef import Zehef

# OSINT extra
from .osint_extra import Cewl, Metagoofil, Exiftool, Maltego, Dmitry, Linkedin2username, Pompem

# Post-exploit
from .post_exploit import EvilWinRM, Koadic, Veil, Shellter, Weevely, Webacoo

# AD / Windows
from .ad_windows import Chntpw, Samdump2, Smbmap

# VoIP / SIP
from .voip import Inviteflood, ProtosSip, Siparmyknife, Sipcrack, Sipp, Sippts, Sipsak, Voiphopper

# System / Other
from .other import Chkrootkit, Lynis, Unhide, Xspy, Yersinia, Macchanger, Socat, Netmask, Pwnat

# Malware / Steganography
from .malware_stegano import Steghide, Outguess, Yara, Capa

# Network extras (arp, dns tools, sniffers)
from .network_extra import ArpScan, ArpSpoof, DnsSpoof, UrlSnarf, MailSnarf, FileSnarf, MsgSnarf, Webmitm, Sshmitm, Dnschef, Dnstracer, Dnsmap, Dnswalk, Ncat, Netcat, Nping, Hping3, Tcpdump, Whois

# Web fuzzing extras
from .web_fuzz import Dirb, Dirsearch, Trufflehog, Gitleaks

# Extra cracking
from .crack_extra2 import Crackle, HashIdentifier, PskCrack, Sucrack, THCPptpBruter, THCSslDos, PoleNum, FernWifiCracker

# Network attack tools
from .network_attack import Dhcpig, Iaxflood, Unicornscan, Oscanner, S3scanner, Sctpscan, SmtpUserEnum, Emails2phonenumber, EnumerateIam

# SSL/Crypto
from .ssl_crypto import Ssldump, Sslsniff, Sslsplit, Sslh, Certipy, LigoloNgProxy

# System enumeration
from .enumeration import LinEnum, LinuxSmartEnum, ShellNoob

# VoIP extras
from .voip_extra import Svmap, Svwar, Svcrack, Svreport, Svcrash

# Cloud extras
from .cloud_extra import Docker

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