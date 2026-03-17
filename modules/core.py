#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar core module — constants, helpers, banner.
"""

import os, sys, io
import socket
import subprocess
import threading
import time
import re
import ipaddress
import json
import importlib.util
from typing import List, Dict, Optional, Tuple

# ══════════════════════════════════════════════════════════════
#  RICH UI  (required)
# ══════════════════════════════════════════════════════════════
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.rule import Rule
    from rich import box
except ImportError:
    print("ERROR: pip install rich")
    sys.exit(1)

console = Console(force_terminal=True, highlight=False)

# ══════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════
VERSION = "2.1.0"

COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 179,
    389, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080, 1194,
    1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3306,
    3389, 3690, 4444, 4848, 5000, 5432, 5900, 5984, 6379,
    7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 9418, 10000, 11211, 27017, 50070,
]
COMMON_UDP_PORTS = {
    53: "DNS", 67: "DHCP", 68: "DHCP-client", 69: "TFTP",
    123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DG",
    161: "SNMP", 162: "SNMP-trap", 500: "IKE/IPSec",
    514: "Syslog", 520: "RIP", 1194: "OpenVPN",
    1900: "SSDP/UPnP", 4500: "IPSec-NAT",
    5353: "mDNS", 5355: "LLMNR",
}
TCP_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-sub", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP",
    3690: "SVN", 5000: "Flask/UPnP", 5432: "PostgreSQL", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 9300: "ES-cluster",
    9418: "Git", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 50070: "Hadoop",
}
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8008, 3000, 4443, 7443, 9443]
SNMP_COMMUNITIES = [
    "public", "private", "community", "admin", "monitor",
    "snmp", "cisco", "default", "guest", "manager", "secret",
]
SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}
DEFAULT_CREDS = {
    21:   [("anonymous", "anonymous"), ("admin", "admin"), ("admin", "password"), ("ftp", "ftp")],
    23:   [("admin", "admin"), ("admin", "password"), ("root", "root")],
    80:   [("admin", "admin"), ("admin", "password"), ("admin", "1234"), ("root", "root")],
    8080: [("admin", "admin"), ("tomcat", "tomcat"), ("manager", "manager")],
    3306: [("root", ""), ("root", "root"), ("admin", "admin")],
    5432: [("postgres", ""), ("postgres", "postgres"), ("admin", "admin")],
}
MDNS_SERVICES = [
    "_http._tcp.local", "_https._tcp.local", "_ssh._tcp.local",
    "_ftp._tcp.local", "_smb._tcp.local", "_airplay._tcp.local",
    "_googlecast._tcp.local", "_printer._tcp.local", "_ipp._tcp.local",
    "_rfb._tcp.local",
]
OUI_DB = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "MS Hyper-V",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:17:88": "Philips Hue", "F0:9F:C2": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "AC:DE:48": "Apple", "F4:F1:5A": "Apple", "28:CF:E9": "Apple",
    "00:1C:B3": "Apple", "78:D7:5A": "Apple", "B4:E6:2D": "Apple",
    "50:C7:BF": "TP-Link", "C0:4A:00": "TP-Link", "18:D6:C7": "TP-Link",
    "F0:27:2D": "TP-Link", "74:DA:38": "TP-Link",
    "00:1D:73": "NETGEAR", "20:4E:7F": "NETGEAR", "A0:63:91": "NETGEAR",
    "C8:D7:19": "ASUS", "00:11:2F": "ASUS", "BC:5F:F4": "ASUS",
    "B0:6E:BF": "Huawei", "00:E0:FC": "Huawei", "48:FD:8E": "Huawei",
    "28:6E:D4": "Intel", "8C:8D:28": "Intel", "3C:77:E6": "Intel",
    "00:23:14": "Dell", "F8:DB:88": "Dell", "14:FE:B5": "Dell",
    "00:50:BA": "D-Link", "14:49:BC": "D-Link", "00:1A:A0": "D-Link",
    "C8:3A:35": "Tenda", "CC:B2:55": "Tenda",
    "54:27:1E": "Samsung", "B8:BC:1B": "Samsung",
    "00:24:E8": "HP", "D8:D3:85": "HP", "68:B5:99": "HP",
    "00:0D:3A": "Microsoft", "28:18:78": "Microsoft",
}

# ══════════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE
# ══════════════════════════════════════════════════════════════
VULN_DB = [
    ("vsftpd",   "2.3.4",    "CVE-2011-2523",  "vsftpd 2.3.4 backdoor shell port 6200",            "CRITICAL"),
    ("proftpd",  "1.3.3",    "CVE-2010-4221",  "ProFTPD 1.3.3 buffer overflow RCE",                "CRITICAL"),
    ("apache",   "2.4.49",   "CVE-2021-41773", "Apache 2.4.49 path traversal + RCE",               "CRITICAL"),
    ("apache",   "2.4.50",   "CVE-2021-42013", "Apache 2.4.50 path traversal bypass",              "CRITICAL"),
    ("apache",   "2.2.",     "CVE-2017-7679",  "Apache 2.2 mod_mime buffer overread",              "HIGH"),
    ("iis",      "6.0",      "CVE-2017-7269",  "IIS 6.0 WebDAV buffer overflow RCE",              "CRITICAL"),
    ("iis",      "5.0",      "CVE-2001-0500",  "IIS 5.0 ISAPI buffer overflow",                   "CRITICAL"),
    ("openssl",  "1.0.1",    "CVE-2014-0160",  "Heartbleed — private key disclosure",              "CRITICAL"),
    ("openssl",  "1.0.2",    "CVE-2016-0800",  "DROWN attack on SSLv2",                           "HIGH"),
    ("openssh",  "2.",       "CVE-2001-0144",  "OpenSSH <2.x critical vulnerabilities",           "CRITICAL"),
    ("openssh",  "4.",       "CVE-2006-5051",  "OpenSSH <4.4 signal handler race condition",      "HIGH"),
    ("openssh",  "6.",       "CVE-2016-0777",  "OpenSSH <7.1p2 roaming info leak",                "MEDIUM"),
    ("samba",    "3.5",      "CVE-2017-7494",  "SambaCry RCE via shared library",                 "CRITICAL"),
    ("samba",    "3.0",      "CVE-2007-2447",  "Samba 3.0 MS-RPC shell metachar injection",      "CRITICAL"),
    ("smb",      "windows",  "CVE-2017-0144",  "EternalBlue SMBv1 RCE (WannaCry)",                "CRITICAL"),
    ("mysql",    "5.5",      "CVE-2012-2122",  "MySQL 5.5 auth bypass via timing",                "HIGH"),
    ("tomcat",   "6.",       "CVE-2017-12617", "Tomcat 6.x JSP upload RCE",                       "CRITICAL"),
    ("tomcat",   "7.0",      "CVE-2019-0232",  "Tomcat 7.0 CGI command injection (Windows)",      "CRITICAL"),
    ("nginx",    "1.3",      "CVE-2013-2028",  "Nginx 1.3 stack buffer overflow",                 "CRITICAL"),
    ("redis",    "",         "CVE-2015-4335",  "Redis unauthenticated Lua RCE",                   "HIGH"),
    ("mongodb",  "",         "CVE-2013-1892",  "MongoDB unauthenticated access (default cfg)",    "HIGH"),
    ("telnet",   "",         "CVE-1999-0619",  "Telnet cleartext + default creds risk",           "HIGH"),
    ("vnc",      "3.",       "CVE-2006-2369",  "VNC 3.x auth bypass (empty password)",            "HIGH"),
    ("ms-wbt",   "",         "CVE-2019-0708",  "BlueKeep RDP pre-auth RCE",                       "CRITICAL"),
    ("weblogic", "",         "CVE-2020-14882", "WebLogic console auth bypass RCE",                "CRITICAL"),
    ("memcached","",         "CVE-2011-4971",  "Memcached DoS via crafted length",                "MEDIUM"),
    ("elasticsearch","1.",   "CVE-2014-3120",  "Elasticsearch 1.x dynamic scripting RCE",         "CRITICAL"),
    ("php",      "5.",       "CVE-2012-1823",  "PHP-CGI 5.x query string injection RCE",          "CRITICAL"),
    ("jenkins",  "",         "CVE-2018-1000861","Jenkins RCE via Stapler URL",                    "CRITICAL"),
]

# ══════════════════════════════════════════════════════════════
#  SNMP PACKET BUILDER (pure Python, no pysnmp needed)
# ══════════════════════════════════════════════════════════════
def _encode_oid(oid_str: str) -> bytes:
    parts  = [int(x) for x in oid_str.split(".")]
    first  = parts[0] * 40 + parts[1]
    result = bytearray([first])
    for part in parts[2:]:
        if part == 0:
            result.append(0)
        else:
            chunks = []
            while part > 0:
                chunks.append(part & 0x7F)
                part >>= 7
            chunks.reverse()
            for i, c in enumerate(chunks):
                result.append(c | (0x80 if i < len(chunks) - 1 else 0))
    return bytes(result)

def _tlv(tag: int, value: bytes) -> bytes:
    le = len(value)
    if le < 128:
        return bytes([tag, le]) + value
    elif le < 256:
        return bytes([tag, 0x81, le]) + value
    else:
        return bytes([tag, 0x82, le >> 8, le & 0xFF]) + value

def build_snmp_get(community: str, oid_str: str, req_id: int = 1) -> bytes:
    oid_bytes   = _encode_oid(oid_str)
    oid_tlv     = _tlv(0x06, oid_bytes)
    null_tlv    = bytes([0x05, 0x00])
    varbind     = _tlv(0x30, oid_tlv + null_tlv)
    varbindlist = _tlv(0x30, varbind)
    rid_raw     = req_id.to_bytes(4, "big").lstrip(b"\x00") or b"\x00"
    req_id_tlv  = _tlv(0x02, rid_raw)
    err_status  = bytes([0x02, 0x01, 0x00])
    err_index   = bytes([0x02, 0x01, 0x00])
    pdu         = _tlv(0xA0, req_id_tlv + err_status + err_index + varbindlist)
    comm        = _tlv(0x04, community.encode())
    version     = bytes([0x02, 0x01, 0x00])
    return _tlv(0x30, version + comm + pdu)

def parse_snmp_string(data: bytes) -> str:
    try:
        results = []
        idx = 0
        while idx < len(data):
            idx = data.find(b"\x04", idx)
            if idx == -1:
                break
            if idx + 1 >= len(data):
                break
            le = data[idx + 1]
            if le & 0x80:
                nb    = le & 0x7F
                le    = int.from_bytes(data[idx + 2: idx + 2 + nb], "big")
                start = idx + 2 + nb
            else:
                start = idx + 2
            val = data[start: start + le]
            try:
                s = val.decode("utf-8", errors="ignore").strip()
                if s and len(s) > 2:
                    results.append(s)
            except Exception:
                pass
            idx = start + le
        return results[1] if len(results) > 1 else (results[0] if results else "")
    except Exception:
        return ""

# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def run_cmd(cmd: list, timeout: int = 15) -> str:
    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=flags)
        try:
            return r.stdout.decode("utf-8", errors="replace")
        except Exception:
            return r.stdout.decode("cp1252", errors="replace")
    except Exception:
        return ""

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_oui_vendor(mac: str) -> str:
    if not mac:
        return ""
    return OUI_DB.get(mac.upper()[:8], "")

def ttl_to_os(ttl: int) -> str:
    if ttl <= 64:   return "Linux/macOS/Android"
    if ttl <= 128:  return "Windows"
    if ttl <= 255:  return "Cisco/Network device"
    return "Unknown"

def severity_color(sev: str) -> str:
    return {"CRITICAL": "red", "HIGH": "orange3",
            "MEDIUM": "yellow", "LOW": "cyan"}.get(sev.upper(), "white")

def _signal_bar(pct: int) -> str:
    filled = round(pct / 20)
    bar    = "█" * filled + "░" * (5 - filled)
    color  = "green" if pct >= 70 else "yellow" if pct >= 40 else "red"
    return f"[{color}]{bar}[/{color}] {pct}%"

def tcp_connect(ip: str, port: int, timeout: float = 0.7) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════
BANNER = r"""
 ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
 ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
"""

def _lib_available(pkg: str) -> bool:
    return importlib.util.find_spec(pkg) is not None

def print_banner():
    mods = []
    for name, pkg in [("scapy","scapy"),("pywifi","pywifi"),("bleak","bleak"),
                      ("dnspython","dns"),("zeroconf","zeroconf")]:
        avail = _lib_available(pkg)
        col   = "green" if avail else "red"
        mods.append(f"[{col}]{name}[/{col}]")
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Panel(
        f"[bold green]NetRadar v{VERSION}[/bold green]  —  "
        "[cyan]Advanced Network Intelligence Scanner[/cyan]\n"
        f"[dim]TCP · UDP · HTTP/S · SSL · DNS · NetBIOS · SNMP · WiFi · BT · mDNS · GeoIP · OSINT · Vulns[/dim]\n"
        f"[dim]Modules: {' '.join(mods)}[/dim]",
        box=box.DOUBLE_EDGE, border_style="cyan"))
