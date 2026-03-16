#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
 ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
              NetRadar v2.0.0 — Advanced Network Intelligence Scanner
"""

import os, sys, io
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.environ.setdefault("PYTHONUTF8", "1")

import socket
import subprocess
import threading
import time
import re
import ipaddress
import argparse
import platform
import json
import ctypes
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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
#  OPTIONAL IMPORTS
# ══════════════════════════════════════════════════════════════
try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import pywifi
    from pywifi import const as wifi_const
    PYWIFI_OK = True
except Exception:
    PYWIFI_OK = False

try:
    from bleak import BleakScanner
    BLEAK_OK = True
except Exception:
    BLEAK_OK = False

try:
    import dns.resolver, dns.reversename, dns.zone, dns.query
    DNSPYTHON_OK = True
except Exception:
    DNSPYTHON_OK = False

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
    ZEROCONF_OK = True
except Exception:
    ZEROCONF_OK = False

# ══════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════
VERSION = "2.0.0"

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

def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    mods = []
    for n, f in [("scapy", SCAPY_OK), ("pywifi", PYWIFI_OK), ("bleak", BLEAK_OK),
                 ("dnspython", DNSPYTHON_OK), ("zeroconf", ZEROCONF_OK)]:
        mods.append(f"[{'green' if f else 'red'}]{n}[/{'green' if f else 'red'}]")
    console.print(Panel(
        f"[bold green]NetRadar v{VERSION}[/bold green]  —  "
        "[cyan]Advanced Network Intelligence Scanner[/cyan]\n"
        f"[dim]TCP · UDP · HTTP/S · SSL · DNS · NetBIOS · SNMP · WiFi · BT · mDNS · GeoIP · Vulns[/dim]\n"
        f"[dim]Modules: {' '.join(mods)}[/dim]",
        box=box.DOUBLE_EDGE, border_style="cyan"
    ))

# ══════════════════════════════════════════════════════════════
#  NETWORK INTERFACES
# ══════════════════════════════════════════════════════════════
def get_interfaces() -> List[Dict]:
    interfaces: List[Dict] = []
    if sys.platform == "win32":
        out = run_cmd(["ipconfig", "/all"])
        cur: Optional[Dict] = None
        IPV4_RE = re.compile(r"ipv4|adresse ipv4|ip address", re.I)
        MASK_RE = re.compile(r"masque|subnet.mask", re.I)
        MAC_RE  = re.compile(r"physique|physical address", re.I)
        IPV6_RE = re.compile(r"ipv6|lien.local", re.I)
        for raw in out.splitlines():
            stripped = raw.strip()
            if raw and not raw[0].isspace() and stripped.endswith(":"):
                if re.search(r"configuration ip|ip configuration", stripped, re.I):
                    continue
                if cur:
                    interfaces.append(cur)
                cur = {"name": stripped.rstrip(":").strip(), "ipv4": [], "ipv6": [], "mac": "N/A"}
            elif cur:
                if MAC_RE.search(stripped):
                    m = re.search(r"([0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2})", stripped)
                    if m:
                        cur["mac"] = m.group(1).replace("-", ":").upper()
                elif IPV4_RE.search(stripped):
                    clean = re.sub(r"\(.*?\)", "", stripped)
                    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", clean)
                    if m and not m.group(1).startswith("169.254"):
                        cur["ipv4"].append({"ip": m.group(1), "netmask": "", "broadcast": ""})
                elif MASK_RE.search(stripped):
                    m = re.search(r"(255\.\d+\.\d+\.\d+)", stripped)
                    if m and cur["ipv4"]:
                        cur["ipv4"][-1]["netmask"] = m.group(1)
                elif IPV6_RE.search(stripped):
                    m = re.search(r"([0-9a-fA-F]{1,4}:[0-9a-fA-F:]{3,})", stripped)
                    if m:
                        cur["ipv6"].append(re.sub(r"%\d+", "", m.group(1).rstrip(":")))
        if cur:
            interfaces.append(cur)
    else:
        out = run_cmd(["ip", "addr", "show"])
        cur = None
        for line in out.splitlines():
            s = line.strip()
            m = re.match(r"^\d+:\s+(\S+):", line)
            if m:
                if cur:
                    interfaces.append(cur)
                cur = {"name": m.group(1), "ipv4": [], "ipv6": [], "mac": "N/A"}
            elif cur:
                m4 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+brd\s+(\S+))?", s)
                if m4:
                    nm = str(ipaddress.IPv4Network(f"0.0.0.0/{m4.group(2)}").netmask)
                    cur["ipv4"].append({"ip": m4.group(1), "netmask": nm, "broadcast": m4.group(3) or ""})
                mm = re.search(r"link/ether\s+([0-9a-fA-F:]+)", s)
                if mm:
                    cur["mac"] = mm.group(1).upper()
        if cur:
            interfaces.append(cur)
    return [i for i in interfaces if i.get("ipv4") or i.get("mac", "N/A") != "N/A"]

def display_interfaces(ifaces: List[Dict]):
    t = Table(title="[bold cyan]Interfaces Réseau[/bold cyan]", box=box.DOUBLE_EDGE,
              header_style="bold magenta", show_lines=True)
    t.add_column("Interface",  style="bold cyan",  min_width=20)
    t.add_column("IPv4",       style="green",      min_width=15)
    t.add_column("Masque",     style="yellow",     min_width=15)
    t.add_column("MAC",        style="red",        min_width=17)
    t.add_column("Vendeur",    style="blue")
    t.add_column("IPv6",       style="dim",        min_width=20)
    for iface in ifaces:
        mac  = iface.get("mac", "N/A")
        ipv6 = ", ".join(iface.get("ipv6", [])[:1])
        rows = iface.get("ipv4") or [{"ip": "", "netmask": ""}]
        for i, addr in enumerate(rows):
            t.add_row(
                iface["name"] if i == 0 else "",
                addr.get("ip", ""), addr.get("netmask", ""),
                mac if i == 0 else "",
                get_oui_vendor(mac) if i == 0 else "",
                ipv6 if i == 0 else "",
            )
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  HOST DISCOVERY
# ══════════════════════════════════════════════════════════════
def ping_host(ip: str) -> Tuple[bool, int]:
    cmd = (["ping", "-n", "1", "-w", "500", ip] if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", "1", ip])
    out   = run_cmd(cmd, timeout=4)
    alive = bool(re.search(r"TTL=\d+", out, re.I))
    m     = re.search(r"TTL=(\d+)", out, re.I)
    return alive, (int(m.group(1)) if m else 64)

def get_arp_table() -> Dict[str, str]:
    arp: Dict[str, str] = {}
    out = run_cmd(["arp", "-a"])
    for line in out.splitlines():
        if sys.platform == "win32":
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})", line)
        else:
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
        if m:
            ip  = m.group(1)
            mac = m.group(2).replace("-", ":").upper()
            if not ip.endswith(".255") and not ip.startswith("224."):
                arp[ip] = mac
    return arp

def scan_network(network: str, cb=None) -> List[Dict]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []
    all_ips = [str(ip) for ip in list(net.hosts())[:512]]
    alive: List[str] = []
    ttl_map: Dict[str, int] = {}
    lock = threading.Lock()
    done = [0]

    def worker(ip):
        ok, ttl = ping_host(ip)
        with lock:
            done[0] += 1
            if ok:
                alive.append(ip)
                ttl_map[ip] = ttl
        if cb:
            cb(done[0], len(all_ips))

    with ThreadPoolExecutor(max_workers=80) as ex:
        list(ex.map(worker, all_ips))

    arp   = get_arp_table()
    hosts = []
    for ip in sorted(alive, key=lambda x: [int(p) for p in x.split(".")]):
        mac = arp.get(ip, "N/A")
        ttl = ttl_map.get(ip, 64)
        hosts.append({
            "ip": ip, "mac": mac, "vendor": get_oui_vendor(mac),
            "hostname": reverse_dns(ip), "ttl": ttl,
            "os": ttl_to_os(ttl), "ports": [], "udp_ports": [],
        })
    return hosts

def display_hosts(hosts: List[Dict]):
    if not hosts:
        console.print("[yellow]Aucun hôte découvert.[/yellow]"); return
    t = Table(title=f"[bold cyan]Hôtes Découverts — {len(hosts)} trouvé(s)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("#",          style="dim",       width=4)
    t.add_column("IP",         style="bold cyan", min_width=15)
    t.add_column("Hostname",   style="green",     min_width=22)
    t.add_column("MAC",        style="red",       min_width=17)
    t.add_column("Vendeur",    style="blue")
    t.add_column("TTL",        style="yellow",    width=5)
    t.add_column("OS (guess)", style="magenta")
    for i, h in enumerate(hosts, 1):
        os_name = h.get("os", "Unknown")
        c = "cyan" if "Windows" in os_name else "green" if "Linux" in os_name else "yellow"
        t.add_row(str(i), h["ip"], h.get("hostname", "") or "[dim]N/A[/dim]",
                  h["mac"], h["vendor"], str(h["ttl"]), f"[{c}]{os_name}[/{c}]")
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  TCP PORT SCANNER
# ══════════════════════════════════════════════════════════════
def tcp_connect(ip: str, port: int, timeout: float = 0.7) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:
        return False

def grab_banner(ip: str, port: int) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        if port in (80, 8080, 8000, 8008):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(512).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""

def scan_ports(ip: str, ports: Optional[List[int]] = None, cb=None) -> List[Dict]:
    if ports is None:
        ports = COMMON_TCP_PORTS
    open_ports: List[Dict] = []
    done = [0]
    lock = threading.Lock()

    def worker(port):
        ok = tcp_connect(ip, port)
        with lock:
            done[0] += 1
        if cb:
            cb(done[0], len(ports))
        if ok:
            return {"port": port, "service": TCP_SERVICES.get(port, "?"),
                    "banner": grab_banner(ip, port)}
        return None

    with ThreadPoolExecutor(max_workers=150) as ex:
        for r in ex.map(worker, ports):
            if r:
                open_ports.append(r)
    return sorted(open_ports, key=lambda x: x["port"])

def display_ports(ip: str, ports: List[Dict]):
    if not ports:
        console.print(f"[yellow]Aucun port TCP ouvert sur {ip}[/yellow]"); return
    t = Table(title=f"[bold cyan]Ports TCP — {ip} ({len(ports)} ouverts)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Port",    style="bold cyan", width=8)
    t.add_column("Service", style="yellow")
    t.add_column("Bannière",style="dim")
    for p in ports:
        t.add_row(str(p["port"]), p["service"], p.get("banner", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  UDP PORT SCANNER
# ══════════════════════════════════════════════════════════════
UDP_PROBES: Dict[int, bytes] = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x01",
}

def scan_udp_port(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    probe = UDP_PROBES.get(port) or build_snmp_get("public", SNMP_OIDS["sysDescr"]) if port == 161 else b"\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(probe, (ip, port))
        data, _ = s.recvfrom(512)
        s.close()
        return data[:40].decode("utf-8", errors="ignore").strip() or "open"
    except socket.timeout:
        return "open|filtered"
    except ConnectionResetError:
        return None
    except Exception:
        return None

def scan_udp(ip: str, cb=None) -> List[Dict]:
    results  = []
    ports    = list(COMMON_UDP_PORTS.keys())
    done     = [0]
    lock     = threading.Lock()

    def worker(port):
        state = scan_udp_port(ip, port)
        with lock:
            done[0] += 1
        if cb:
            cb(done[0], len(ports))
        if state and state != "open|filtered":
            return {"port": port, "service": COMMON_UDP_PORTS.get(port, "?"),
                    "state": "open", "info": state[:40]}
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for r in ex.map(worker, ports):
            if r:
                results.append(r)
    return sorted(results, key=lambda x: x["port"])

def display_udp(ip: str, ports: List[Dict]):
    if not ports:
        console.print(f"[yellow]Aucun port UDP ouvert détecté sur {ip}[/yellow]"); return
    t = Table(title=f"[bold cyan]Ports UDP — {ip} ({len(ports)} ouverts)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Port",    style="bold cyan", width=8)
    t.add_column("Service", style="yellow")
    t.add_column("Info",    style="dim")
    for p in ports:
        t.add_row(str(p["port"]), p["service"], p.get("info", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  HTTP / HTTPS SCANNER
# ══════════════════════════════════════════════════════════════
def scan_http(ip: str, port: int = 80, https: bool = False) -> Dict:
    scheme = "https" if https else "http"
    url    = f"{scheme}://{ip}:{port}/"
    result: Dict = {"ip": ip, "port": port, "scheme": scheme, "status": None,
                    "server": "", "title": "", "techs": [], "headers": {},
                    "redirect": "", "error": "", "rtime_ms": 0}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (NetRadar/2.0)"})
        t0  = time.time()
        with urllib.request.urlopen(req, timeout=5, context=(ctx if https else None)) as r:
            result["status"]   = r.status
            result["headers"]  = dict(r.headers)
            result["server"]   = r.headers.get("Server", "")
            result["rtime_ms"] = int((time.time() - t0) * 1000)
            if r.url != url:
                result["redirect"] = r.url[:80]
            body = r.read(8192).decode("utf-8", errors="ignore")
            tm   = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if tm:
                result["title"] = tm.group(1).strip()[:80]
    except urllib.error.HTTPError as e:
        result["status"] = e.code
    except Exception as e:
        result["error"] = str(e)[:60]

    techs  = []
    srv    = result["server"].lower()
    hdr    = {k.lower(): v for k, v in result["headers"].items()}
    for pat, name in [("apache", "Apache"), ("nginx", "Nginx"), ("iis", "IIS"),
                      ("tomcat", "Tomcat"), ("gunicorn", "Gunicorn"),
                      ("werkzeug", "Flask"), ("caddy", "Caddy"), ("lighttpd", "lighttpd"),
                      ("kestrel", ".NET")]:
        if pat in srv:
            techs.append(name)
    if hdr.get("x-powered-by"):
        techs.append(f"[{hdr['x-powered-by'][:20]}]")
    if hdr.get("x-aspnet-version"):
        techs.append(f"ASP.NET {hdr['x-aspnet-version']}")
    sec = []
    if "strict-transport-security" in hdr: sec.append("HSTS")
    if "content-security-policy"   in hdr: sec.append("CSP")
    if "x-frame-options"           in hdr: sec.append("XFO")
    if sec:
        techs.append("Sec:" + "+".join(sec))
    result["techs"] = techs
    return result

def display_http(results: List[Dict]):
    if not results:
        console.print("[yellow]Aucun service HTTP trouvé.[/yellow]"); return
    t = Table(title="[bold cyan]Scanner HTTP/HTTPS[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP:Port",  style="bold cyan",  min_width=22)
    t.add_column("Code",     style="yellow",     width=6)
    t.add_column("Serveur",  style="green")
    t.add_column("Titre",    style="white",      min_width=25)
    t.add_column("Techs",    style="blue")
    t.add_column("ms",       style="dim",        width=6)
    for r in results:
        st = r.get("status")
        sc = (f"[green]{st}[/green]" if st and st < 300 else
              f"[yellow]{st}[/yellow]" if st and st < 400 else
              f"[red]{st}[/red]" if st else "[dim]ERR[/dim]")
        t.add_row(f"{r['scheme']}://{r['ip']}:{r['port']}",
                  sc, r.get("server", ""), r.get("title", ""),
                  ", ".join(r.get("techs", [])), str(r.get("rtime_ms", "")))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  SSL / TLS CERTIFICATE SCANNER
# ══════════════════════════════════════════════════════════════
def scan_ssl(ip: str, port: int = 443) -> Dict:
    result: Dict = {"ip": ip, "port": port, "cn": "", "issuer": "",
                    "valid_from": "", "valid_to": "", "days_left": 0,
                    "san": [], "cipher": "", "version": "", "expired": False, "error": ""}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cert   = s.getpeercert()
                cipher = s.cipher()
                if cipher:
                    result["cipher"]  = cipher[0]
                    result["version"] = cipher[1]
                if cert:
                    subj   = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["cn"]         = subj.get("commonName", "")
                    result["issuer"]     = issuer.get("organizationName", issuer.get("commonName", ""))
                    result["valid_from"] = cert.get("notBefore", "")
                    result["valid_to"]   = cert.get("notAfter", "")
                    result["san"]        = [x[1] for x in cert.get("subjectAltName", [])][:6]
                    try:
                        exp  = datetime.strptime(result["valid_to"], "%b %d %H:%M:%S %Y %Z")
                        dl   = (exp - datetime.utcnow()).days
                        result["days_left"] = dl
                        result["expired"]   = dl < 0
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)[:60]
    return result

def display_ssl(results: List[Dict]):
    if not results:
        console.print("[yellow]Aucun résultat SSL.[/yellow]"); return
    t = Table(title="[bold cyan]Certificats SSL/TLS[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP:Port",     style="bold cyan",  min_width=20)
    t.add_column("CN",          style="green",      min_width=22)
    t.add_column("Issuer",      style="yellow")
    t.add_column("Expiry",      style="white",      min_width=12)
    t.add_column("Jours rest.", style="white",      width=10)
    t.add_column("SANs",        style="dim")
    t.add_column("Cipher",      style="blue")
    for r in results:
        dl  = r.get("days_left", 0)
        dc  = "red" if dl < 0 else "yellow" if dl < 30 else "green"
        dl_s = f"[{dc}]{dl}j[/{dc}]"
        t.add_row(f"{r['ip']}:{r['port']}",
                  r.get("cn", ""), r.get("issuer", ""),
                  r.get("valid_to", "")[:11], dl_s,
                  ", ".join(r.get("san", [])[:3]), r.get("cipher", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  DNS RECORD SCANNER
# ══════════════════════════════════════════════════════════════
def scan_dns(target: str) -> Dict:
    result: Dict = {"target": target, "records": {}, "reverse": "", "zone_transfer": []}
    if is_valid_ip(target):
        result["reverse"] = reverse_dns(target)
        return result
    if DNSPYTHON_OK:
        r = dns.resolver.Resolver()
        r.timeout = r.lifetime = 5
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                ans = r.resolve(target, rtype)
                result["records"][rtype] = [str(x) for x in ans]
            except Exception:
                pass
        for ns in result["records"].get("NS", [])[:1]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns.rstrip("."), target, timeout=5))
                result["zone_transfer"] = [str(k) for k in z.nodes.keys()][:20]
            except Exception:
                pass
    else:
        try:
            result["records"]["A"] = list({r[4][0] for r in
                socket.getaddrinfo(target, None, socket.AF_INET)})
        except Exception:
            pass
    return result

def display_dns(result: Dict):
    t = Table(title=f"[bold cyan]DNS — {result['target']}[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Type",   style="bold yellow", width=8)
    t.add_column("Valeur", style="green")
    if result.get("reverse"):
        t.add_row("PTR", result["reverse"])
    for rtype, vals in result.get("records", {}).items():
        for v in vals:
            t.add_row(rtype, str(v)[:120])
    if result.get("zone_transfer"):
        t.add_row("[bold red]AXFR[/bold red]",
                  f"[red]Zone transfer OK! {len(result['zone_transfer'])} entrées[/red]")
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  NETBIOS / SMB SCANNER
# ══════════════════════════════════════════════════════════════
def scan_netbios(ip: str) -> Dict:
    result = {"ip": ip, "name": "", "domain": "", "mac": "", "services": []}
    if sys.platform == "win32":
        out = run_cmd(["nbtstat", "-A", ip], timeout=10)
        n = re.search(r"(\S+)\s+<00>\s+UNIQUE\s+Registered", out)
        if n:
            result["name"] = n.group(1)
        d = re.search(r"(\S+)\s+<00>\s+GROUP\s+Registered", out)
        if d:
            result["domain"] = d.group(1)
        m = re.search(r"MAC Address\s*=\s*([0-9A-Fa-f-]+)", out, re.I)
        if m:
            result["mac"] = m.group(1).replace("-", ":").upper()
    else:
        out = run_cmd(["nmblookup", "-A", ip], timeout=10)
        for line in out.splitlines():
            m = re.search(r"(\S+)\s+<00>\s+[^\[]", line)
            if m:
                result["name"] = m.group(1)
    return result

def display_netbios(results: List[Dict]):
    if not results:
        console.print("[yellow]Aucune info NetBIOS trouvée.[/yellow]"); return
    t = Table(title="[bold cyan]NetBIOS / SMB[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP",      style="bold cyan",  min_width=15)
    t.add_column("Nom",     style="green",      min_width=15)
    t.add_column("Domaine", style="yellow")
    t.add_column("MAC",     style="red",        min_width=17)
    for r in results:
        t.add_row(r["ip"], r.get("name", ""), r.get("domain", ""), r.get("mac", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  SNMP SCANNER
# ══════════════════════════════════════════════════════════════
def scan_snmp(ip: str) -> Dict:
    result = {"ip": ip, "community": None, "sysDescr": "", "sysName": "", "sysLocation": ""}
    for comm in SNMP_COMMUNITIES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(build_snmp_get(comm, SNMP_OIDS["sysDescr"]), (ip, 161))
            data, _ = s.recvfrom(1024)
            s.close()
            descr = parse_snmp_string(data)
            if descr:
                result["community"] = comm
                result["sysDescr"]  = descr[:80]
                for field, oid_key in [("sysName", "sysName"), ("sysLocation", "sysLocation")]:
                    try:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s2.settimeout(2)
                        s2.sendto(build_snmp_get(comm, SNMP_OIDS[oid_key]), (ip, 161))
                        d2, _ = s2.recvfrom(512)
                        s2.close()
                        result[field] = parse_snmp_string(d2)[:60]
                    except Exception:
                        pass
                return result
        except Exception:
            pass
    return result

def display_snmp(results: List[Dict]):
    active = [r for r in results if r.get("community")]
    if not active:
        console.print("[yellow]Aucun appareil SNMP accessible.[/yellow]"); return
    t = Table(title=f"[bold cyan]SNMP — {len(active)} appareil(s)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP",        style="bold cyan",  min_width=15)
    t.add_column("Community", style="red",        width=12)
    t.add_column("sysDescr",  style="green",      min_width=30)
    t.add_column("sysName",   style="yellow")
    t.add_column("Location",  style="dim")
    for r in active:
        t.add_row(r["ip"], r.get("community", ""), r.get("sysDescr", ""),
                  r.get("sysName", ""), r.get("sysLocation", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  TRACEROUTE
# ══════════════════════════════════════════════════════════════
def run_traceroute(target: str, max_hops: int = 20) -> List[Dict]:
    if sys.platform == "win32":
        cmd    = ["tracert", "-d", "-h", str(max_hops), target]
        hop_re = re.compile(r"^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+|\*)\s*$")
        lat_re = re.compile(r"(\d+)\s*ms")
    else:
        cmd    = ["traceroute", "-n", "-m", str(max_hops), target]
        hop_re = re.compile(r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)")
        lat_re = re.compile(r"(\d+\.?\d*)\s*ms")
    out  = run_cmd(cmd, timeout=60)
    hops = []
    for line in out.splitlines():
        m = hop_re.search(line)
        if m:
            ip      = m.group(2) if sys.platform != "win32" else m.group(2)
            lats    = lat_re.findall(line)
            latency = f"{lats[0]} ms" if lats else "*"
            hops.append({"hop": int(m.group(1)), "ip": ip,
                         "latency": latency,
                         "hostname": reverse_dns(ip) if ip != "*" else ""})
    return hops

def display_traceroute(target: str, hops: List[Dict]):
    t = Table(title=f"[bold cyan]Traceroute → {target}[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("#",        style="dim",       width=4)
    t.add_column("IP",       style="bold cyan", min_width=15)
    t.add_column("Hostname", style="green",     min_width=25)
    t.add_column("Latence",  style="yellow")
    for h in hops:
        ip = h.get("ip", "*")
        c  = "dim" if ip == "*" else "bold cyan"
        t.add_row(str(h["hop"]), f"[{c}]{ip}[/{c}]",
                  h.get("hostname", ""), h.get("latency", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  IP GEOLOCATION
# ══════════════════════════════════════════════════════════════
def geolocate(ip: str) -> Dict:
    if is_private_ip(ip) or ip.startswith("127."):
        return {"query": ip, "status": "private", "country": "Local/Privé",
                "regionName": "", "city": "", "isp": "", "org": "", "as": "",
                "lat": 0, "lon": 0}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,query"
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"query": ip, "status": "fail", "country": "", "regionName": "",
                "city": "", "isp": str(e)[:40], "org": "", "as": "", "lat": 0, "lon": 0}

def display_geolocate(results: List[Dict]):
    t = Table(title="[bold cyan]Géolocalisation IP[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP",      style="bold cyan",  min_width=15)
    t.add_column("Pays",    style="green")
    t.add_column("Région",  style="yellow")
    t.add_column("Ville",   style="white")
    t.add_column("ISP",     style="blue")
    t.add_column("AS",      style="dim")
    t.add_column("Coords",  style="dim")
    for r in results:
        t.add_row(r.get("query", ""),
                  r.get("country", ""), r.get("regionName", ""),
                  r.get("city", ""), r.get("isp", "")[:30],
                  r.get("as", "")[:20],
                  f"{r.get('lat','')} , {r.get('lon','')}")
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  WHOIS
# ══════════════════════════════════════════════════════════════
def whois_lookup(target: str) -> str:
    try:
        server = "whois.arin.net" if is_valid_ip(target) else "whois.iana.org"
        with socket.create_connection((server, 43), timeout=10) as s:
            s.send((target + "\r\n").encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
            text = raw.decode("utf-8", errors="ignore")
            ref  = re.search(r"refer:\s*(\S+)", text, re.I)
            if ref:
                with socket.create_connection((ref.group(1), 43), timeout=10) as s2:
                    s2.send((target + "\r\n").encode())
                    raw2 = b""
                    while True:
                        ch = s2.recv(4096)
                        if not ch:
                            break
                        raw2 += ch
                    text = raw2.decode("utf-8", errors="ignore")
            lines = [l for l in text.splitlines()
                     if l.strip() and not l.startswith("%") and not l.startswith("#")]
            return "\n".join(lines[:40])
    except Exception as e:
        return f"Erreur WHOIS: {e}"

def display_whois(target: str, text: str):
    console.print(Panel(text[:2000], title=f"[bold cyan]WHOIS — {target}[/bold cyan]",
                        border_style="cyan"))

# ══════════════════════════════════════════════════════════════
#  MDNS / ZEROCONF
# ══════════════════════════════════════════════════════════════
def scan_mdns(timeout: float = 5.0) -> List[Dict]:
    devices: List[Dict] = []
    if ZEROCONF_OK:
        lock = threading.Lock()
        def on_change(zc, service_type, name, state_change):
            if str(state_change) == "ServiceStateChange.Added":
                info = zc.get_service_info(service_type, name)
                if info:
                    ips = [socket.inet_ntoa(a) for a in info.addresses]
                    with lock:
                        devices.append({"name": name, "type": service_type,
                                        "ip": ips[0] if ips else "",
                                        "port": info.port, "server": info.server or ""})
        zc = Zeroconf()
        for st in MDNS_SERVICES:
            ServiceBrowser(zc, st, handlers=[on_change])
        time.sleep(timeout)
        zc.close()
        return devices

    query = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(query, ("224.0.0.251", 5353))
        seen    = set()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(2048)
                ip = addr[0]
                if ip not in seen:
                    seen.add(ip)
                    devices.append({"name": reverse_dns(ip) or ip, "type": "mDNS",
                                    "ip": ip, "port": 5353, "server": ""})
            except socket.timeout:
                break
        s.close()
    except Exception:
        pass
    return devices

def display_mdns(devices: List[Dict]):
    if not devices:
        console.print("[yellow]Aucun service mDNS détecté.[/yellow]"); return
    t = Table(title=f"[bold cyan]Services mDNS/Zeroconf — {len(devices)} trouvé(s)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Nom",     style="bold cyan",  min_width=30)
    t.add_column("Type",    style="yellow")
    t.add_column("IP",      style="green",      min_width=15)
    t.add_column("Port",    style="red",        width=7)
    t.add_column("Serveur", style="dim")
    for d in devices:
        t.add_row(d.get("name", ""), d.get("type", ""), d.get("ip", ""),
                  str(d.get("port", "")), d.get("server", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  VULNERABILITY HINTS
# ══════════════════════════════════════════════════════════════
def check_vulns(hosts: List[Dict]) -> List[Dict]:
    findings = []
    for host in hosts:
        for port_info in host.get("ports", []):
            text = (port_info.get("banner", "") + " " +
                    port_info.get("service", "")).lower()
            for svc_kw, ver_kw, cve, desc, sev in VULN_DB:
                if svc_kw and svc_kw not in text:
                    continue
                if ver_kw and ver_kw not in text:
                    continue
                if not svc_kw and not ver_kw:
                    continue
                findings.append({"ip": host["ip"], "port": port_info["port"],
                                  "cve": cve, "desc": desc, "severity": sev})
    return findings

def display_vulns(findings: List[Dict]):
    if not findings:
        console.print("[green]Aucune vulnérabilité détectée dans les bannières.[/green]"); return
    t = Table(title=f"[bold red]Vulnérabilités Potentielles — {len(findings)} trouvée(s)[/bold red]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP:Port",       style="bold cyan",  min_width=18)
    t.add_column("CVE",           style="yellow",     min_width=16)
    t.add_column("Sévérité",      width=10)
    t.add_column("Description",   style="white",      min_width=45)
    for f in findings:
        sev = f.get("severity", "?")
        sc  = severity_color(sev)
        t.add_row(f"{f['ip']}:{f['port']}", f["cve"],
                  f"[{sc}][bold]{sev}[/bold][/{sc}]", f["desc"])
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  NETWORK STATISTICS
# ══════════════════════════════════════════════════════════════
def get_net_stats() -> Dict:
    stats: Dict = {"raw": {}, "connections": {}}
    if sys.platform == "win32":
        out = run_cmd(["netstat", "-e"], timeout=10)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit():
                stats["raw"]["bytes_recv"] = int(parts[1])
                stats["raw"]["bytes_sent"] = int(parts[2])
                break
        out2 = run_cmd(["netstat", "-an"], timeout=10)
        states: Dict[str, int] = {}
        for line in out2.splitlines():
            m = re.search(r"\b(ESTABLISHED|LISTENING|TIME_WAIT|CLOSE_WAIT|SYN_SENT|FIN_WAIT)\b",
                          line, re.I)
            if m:
                s = m.group(1).upper()
                states[s] = states.get(s, 0) + 1
        stats["connections"] = states
    return stats

def display_netstats(stats: Dict):
    t = Table(title="[bold cyan]Statistiques Réseau[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Métrique", style="bold yellow")
    t.add_column("Valeur",   style="green")
    raw = stats.get("raw", {})
    if "bytes_recv" in raw:
        t.add_row("Bytes reçus",   f"{raw['bytes_recv']:,}")
        t.add_row("Bytes envoyés", f"{raw['bytes_sent']:,}")
    for state, count in sorted(stats.get("connections", {}).items()):
        t.add_row(f"TCP {state}", str(count))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  DEFAULT CREDENTIALS CHECKER
# ══════════════════════════════════════════════════════════════
def check_default_creds(ip: str, port: int) -> List[Dict]:
    results = []
    for user, passwd in DEFAULT_CREDS.get(port, []):
        ok = False
        try:
            if port == 21:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(ip, 21, timeout=5)
                ftp.login(user, passwd)
                ftp.quit()
                ok = True
            elif port in (80, 8080):
                import base64
                cred64 = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                req = urllib.request.Request(
                    f"http://{ip}:{port}/",
                    headers={"Authorization": f"Basic {cred64}",
                             "User-Agent": "NetRadar/2.0"})
                try:
                    with urllib.request.urlopen(req, timeout=4):
                        ok = True
                except urllib.error.HTTPError as e:
                    ok = e.code not in (401, 403)
        except Exception:
            pass
        if ok:
            results.append({"ip": ip, "port": port, "user": user,
                             "password": passwd, "status": "SUCCESS"})
    return results

def display_default_creds(findings: List[Dict]):
    if not findings:
        console.print("[green]Aucun credential par défaut trouvé.[/green]"); return
    t = Table(title=f"[bold red]Credentials Défaut — {len(findings)} trouvé(s)[/bold red]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("IP:Port",  style="bold cyan",  min_width=20)
    t.add_column("User",     style="yellow")
    t.add_column("Password", style="red")
    t.add_column("Statut",   style="bold green")
    for f in findings:
        t.add_row(f"{f['ip']}:{f['port']}", f["user"], f["password"], f["status"])
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  WIFI SCANNER
# ══════════════════════════════════════════════════════════════
def _wifi_netsh() -> List[Dict]:
    out  = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20)
    nets: List[Dict] = []
    cur: Dict = {}
    for raw in out.splitlines():
        line = raw.strip()
        m_ssid = re.match(r"^SSID\s+\d+\s*:\s*(.*)", line)
        if m_ssid and "BSSID" not in line:
            if cur.get("ssid") is not None:
                nets.append(cur)
            cur = {"ssid": m_ssid.group(1).strip()}
            continue
        if not cur:
            continue
        if re.search(r"BSSID\s+\d+\s*:", line, re.I):
            m = re.search(r"BSSID\s+\d+\s*:\s*(\S+)", line, re.I)
            if m:
                cur["bssid"] = m.group(1).upper()
        ms = re.search(r"Signal\s*:\s*(\d+)%", line)
        if ms:
            p = int(ms.group(1))
            cur["signal_pct"] = p
            cur["signal_dbm"] = f"{p/2-100:.0f} dBm"
        ma = re.search(r"Authentication\s*:\s*(.*)", line)
        if ma:
            cur["auth"] = ma.group(1).strip()
        mc = re.search(r"Channel\s*:\s*(\d+)", line)
        if mc:
            cur["channel"] = mc.group(1)
        mr = re.search(r"Radio type\s*:\s*(.*)", line)
        if mr:
            cur["radio"] = mr.group(1).strip()
    if cur.get("ssid") is not None:
        nets.append(cur)
    return nets

def scan_wifi() -> List[Dict]:
    if PYWIFI_OK:
        try:
            wifi  = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(3)
            nets = []
            for r in iface.scan_results():
                akm     = r.akm[0] if r.akm else 0
                auth_map = {wifi_const.AKM_TYPE_NONE: "Open", wifi_const.AKM_TYPE_WPA: "WPA",
                            wifi_const.AKM_TYPE_WPAPSK: "WPA-PSK", wifi_const.AKM_TYPE_WPA2: "WPA2",
                            wifi_const.AKM_TYPE_WPA2PSK: "WPA2-PSK"}
                pct = min(100, max(0, 2 * (r.signal + 100)))
                nets.append({"ssid": r.ssid or "[Caché]", "bssid": (r.bssid or "").upper(),
                              "signal_pct": pct, "signal_dbm": f"{r.signal} dBm",
                              "auth": auth_map.get(akm, "?"), "channel": "?", "radio": "?"})
            if nets:
                return nets
        except Exception:
            pass
    if sys.platform == "win32":
        return _wifi_netsh()
    out  = run_cmd(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi", "list"])
    nets = []
    for line in out.strip().splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 4:
            pct = int(parts[2]) if parts[2].isdigit() else 0
            nets.append({"ssid": parts[0] or "[Caché]", "bssid": parts[1].replace("\\:", ":").upper(),
                         "signal_pct": pct, "signal_dbm": f"{pct//2-100} dBm",
                         "auth": parts[3], "channel": parts[4] if len(parts) > 4 else "?", "radio": "?"})
    return nets

def display_wifi(nets: List[Dict]):
    if not nets:
        console.print("[yellow]Aucun réseau WiFi trouvé.[/yellow]"); return
    nets.sort(key=lambda x: x.get("signal_pct", 0), reverse=True)
    t = Table(title=f"[bold cyan]Réseaux WiFi — {len(nets)} trouvé(s)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("SSID",     style="bold cyan",  min_width=22)
    t.add_column("BSSID",    style="red",        min_width=17)
    t.add_column("Signal",   style="yellow",     width=10)
    t.add_column("Force",    min_width=12)
    t.add_column("Canal",    style="blue",       width=7)
    t.add_column("Sécurité", min_width=12)
    t.add_column("Vendeur",  style="blue")
    for n in nets:
        pct  = n.get("signal_pct", 0)
        auth = n.get("auth", "?")
        bss  = n.get("bssid", "")
        sc   = "red" if auth in ("Open", "None", "") else "green"
        t.add_row(n.get("ssid", "[Caché]"), bss, n.get("signal_dbm", ""),
                  _signal_bar(pct), str(n.get("channel", "?")),
                  f"[{sc}]{auth}[/{sc}]", get_oui_vendor(bss))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  BLUETOOTH SCANNER
# ══════════════════════════════════════════════════════════════
async def _ble_scan(timeout: float = 8.0) -> List[Dict]:
    devs = []
    try:
        for d in await BleakScanner.discover(timeout=timeout):
            devs.append({"name": d.name or "[?]", "address": d.address.upper(),
                         "rssi": d.rssi, "type": "BLE", "status": "Découvert"})
    except Exception:
        pass
    return devs

def _bt_powershell() -> List[Dict]:
    devs = []
    out  = run_cmd(["powershell", "-Command",
                    "Get-PnpDevice -Class Bluetooth | "
                    "Select-Object FriendlyName,DeviceID,Status | ConvertTo-Json"], timeout=20)
    try:
        raw = json.loads(out.strip())
        if isinstance(raw, dict):
            raw = [raw]
        for item in raw:
            if not isinstance(item, dict):
                continue
            name   = item.get("FriendlyName", "?") or "?"
            dev_id = item.get("DeviceID", "") or ""
            clean  = re.sub(r"[^0-9A-Fa-f]", "", dev_id)
            mac    = (":".join(clean[i:i+2] for i in range(0, 12, 2)).upper()
                      if len(clean) >= 12 else "N/A")
            devs.append({"name": name, "address": mac, "rssi": "N/A",
                         "type": "BT/BLE", "status": item.get("Status", "?")})
    except Exception:
        pass
    return devs

def scan_bluetooth() -> List[Dict]:
    devs: List[Dict] = []
    if BLEAK_OK:
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            devs.extend(loop.run_until_complete(_ble_scan()))
            loop.close()
        except Exception:
            pass
    if not devs and sys.platform == "win32":
        devs.extend(_bt_powershell())
    return devs

def display_bluetooth(devs: List[Dict]):
    if not devs:
        console.print("[yellow]Aucun appareil Bluetooth trouvé.[/yellow]"); return
    t = Table(title=f"[bold cyan]Bluetooth — {len(devs)} appareil(s)[/bold cyan]",
              box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
    t.add_column("Nom",     style="bold cyan",  min_width=22)
    t.add_column("Adresse", style="red",        min_width=17)
    t.add_column("RSSI",    style="yellow",     width=10)
    t.add_column("Type",    style="green")
    t.add_column("Statut",  style="dim")
    for d in devs:
        r = d.get("rssi", "N/A")
        if isinstance(r, int):
            c  = "green" if r >= -70 else "yellow" if r >= -90 else "red"
            rs = f"[{c}]{r} dBm[/{c}]"
        else:
            rs = str(r)
        t.add_row(d.get("name", "?"), d.get("address", ""), rs,
                  d.get("type", ""), d.get("status", ""))
    console.print(t)

# ══════════════════════════════════════════════════════════════
#  LIVE PACKET CAPTURE
# ══════════════════════════════════════════════════════════════
def live_capture(iface: Optional[str] = None, count: int = 100):
    if not SCAPY_OK:
        console.print("[red]Scapy requis. pip install scapy[/red]")
        if sys.platform == "win32":
            console.print("[yellow]Installez Npcap: npcap.com[/yellow]")
        return
    console.print(f"[dim]{'#':>5}  {'Heure':12}  {'Src IP':15}  {'Dst IP':15}  "
                  f"{'Proto':8}  {'Src MAC':17}  Info[/dim]")
    console.print("[dim]" + "─" * 110 + "[/dim]")
    n = [0]

    def cb(pkt):
        n[0] += 1
        try:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
            src_ip = dst_ip = proto = src_mac = info = ""
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.upper()
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    sp = pkt[TCP].sport; dp = pkt[TCP].dport
                    svc = TCP_SERVICES.get(dp, TCP_SERVICES.get(sp, ""))
                    info = f"{sp}→{dp} [{pkt[TCP].flags}]" + (f" ({svc})" if svc else "")
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    info  = f"{pkt[UDP].sport}→{pkt[UDP].dport}"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
                    info  = {0: "Echo Reply", 8: "Echo Req", 3: "Unreachable",
                             11: "TTL Exceed"}.get(pkt[ICMP].type, f"T{pkt[ICMP].type}")
                else:
                    proto = f"IP/{pkt[IP].proto}"
            elif pkt.haslayer(ARP):
                proto  = "ARP"
                src_ip = pkt[ARP].psrc; dst_ip = pkt[ARP].pdst
                src_mac = pkt[ARP].hwsrc.upper()
                info    = "Who has?" if pkt[ARP].op == 1 else "Is at"
            if src_ip or proto:
                console.print(
                    f"[dim]{n[0]:>5}[/dim]  [dim]{ts}[/dim]  "
                    f"[cyan]{src_ip or 'N/A':15}[/cyan]  [red]{dst_ip or 'N/A':15}[/red]  "
                    f"[yellow]{proto or '?':8}[/yellow]  [green]{src_mac or 'N/A':17}[/green]  "
                    f"[dim]{info}[/dim]"
                )
        except Exception:
            pass
        if n[0] >= count:
            return True

    try:
        scapy.sniff(iface=iface, prn=cb, count=count, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        if sys.platform == "win32":
            console.print("[yellow]→ Npcap + Administrateur requis[/yellow]")
    console.print(f"\n[green]{n[0]} paquets capturés.[/green]")

# ══════════════════════════════════════════════════════════════
#  FULL SCAN
# ══════════════════════════════════════════════════════════════
def _auto_nets(ifaces: List[Dict]) -> List[str]:
    nets = []
    for iface in ifaces:
        for addr in iface.get("ipv4", []):
            ip = addr.get("ip", ""); mask = addr.get("netmask", "")
            if ip and mask and not ip.startswith("127.") and not ip.startswith("169.254."):
                try:
                    n = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    if n.prefixlen >= 16:
                        nets.append(str(n))
                except Exception:
                    pass
    if not nets:
        local = get_local_ip()
        nets.append(".".join(local.split(".")[:3]) + ".0/24")
    return list(dict.fromkeys(nets))

def full_scan() -> Dict:
    console.print(Rule("[bold cyan]  NETRADAR v2.0 — SCAN COMPLET  [/bold cyan]", style="cyan"))

    # 1 — Interfaces
    console.print("\n[bold yellow][1/9]  Interfaces Réseau[/bold yellow]")
    ifaces = get_interfaces()
    display_interfaces(ifaces)
    nets   = _auto_nets(ifaces)

    # 2 — Host discovery
    console.print(f"\n[bold yellow][2/9]  Découverte Hôtes — {', '.join(nets)}[/bold yellow]")
    all_hosts: List[Dict] = []
    for net in nets:
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]{net}"),
                      BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
                      console=console) as prog:
            task = prog.add_task(net, total=256)
            def cb(d, t, _t=task, _p=prog): _p.update(_t, completed=d, total=t)
            all_hosts.extend(scan_network(net, cb))
    display_hosts(all_hosts)

    # 3 — TCP port scan
    console.print(f"\n[bold yellow][3/9]  Scan Ports TCP[/bold yellow]")
    for host in all_hosts[:20]:
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]TCP {host['ip']}"),
                      BarColumn(bar_width=25), TextColumn("{task.percentage:>3.0f}%"),
                      console=console) as prog:
            task = prog.add_task("", total=len(COMMON_TCP_PORTS))
            def pcb(d, t, _t=task, _p=prog): _p.update(_t, completed=d)
            host["ports"] = scan_ports(host["ip"], cb=pcb)
        display_ports(host["ip"], host["ports"])

    # 4 — HTTP/HTTPS
    console.print(f"\n[bold yellow][4/9]  Scanner HTTP/HTTPS[/bold yellow]")
    http_results = []
    for host in all_hosts[:20]:
        for p in host.get("ports", []):
            port  = p["port"]
            https = port in (443, 8443, 4443, 7443, 9443)
            if port in HTTP_PORTS:
                http_results.append(scan_http(host["ip"], port, https))
    display_http(http_results)

    # 5 — SSL
    console.print(f"\n[bold yellow][5/9]  Certificats SSL/TLS[/bold yellow]")
    ssl_results = []
    for host in all_hosts[:20]:
        for p in host.get("ports", []):
            if p["port"] in (443, 8443, 4443, 7443, 9443):
                ssl_results.append(scan_ssl(host["ip"], p["port"]))
    display_ssl(ssl_results)

    # 6 — SNMP
    console.print(f"\n[bold yellow][6/9]  Scanner SNMP[/bold yellow]")
    snmp_results = []
    for host in all_hosts[:15]:
        if any(p["port"] == 161 for p in host.get("ports", [])):
            snmp_results.append(scan_snmp(host["ip"]))
    if snmp_results:
        display_snmp(snmp_results)
    else:
        console.print("[dim]Aucun port SNMP (161) ouvert détecté.[/dim]")

    # 7 — WiFi
    console.print(f"\n[bold yellow][7/9]  Réseaux WiFi[/bold yellow]")
    with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]Scan WiFi..."),
                  console=console) as p:
        p.add_task("", total=None)
        wifi_nets = scan_wifi()
    display_wifi(wifi_nets)

    # 8 — Bluetooth
    console.print(f"\n[bold yellow][8/9]  Bluetooth[/bold yellow]")
    with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]Scan BT (~8s)..."),
                  console=console) as p:
        p.add_task("", total=None)
        bt_devs = scan_bluetooth()
    display_bluetooth(bt_devs)

    # 9 — Vulnérabilités
    console.print(f"\n[bold yellow][9/9]  Analyse Vulnérabilités[/bold yellow]")
    vulns = check_vulns(all_hosts)
    display_vulns(vulns)

    # Summary
    console.print()
    console.print(Rule("[bold green]  SCAN TERMINÉ  [/bold green]", style="green"))
    t = Table(box=box.ROUNDED, show_header=False, border_style="green", padding=(0, 3))
    t.add_column("", style="bold"); t.add_column("", style="bold cyan")
    t.add_row("Interfaces",          str(len(ifaces)))
    t.add_row("Hôtes découverts",    str(len(all_hosts)))
    t.add_row("Ports TCP ouverts",   str(sum(len(h["ports"]) for h in all_hosts)))
    t.add_row("Services HTTP/HTTPS", str(len(http_results)))
    t.add_row("Certificats SSL",     str(len(ssl_results)))
    t.add_row("Réseaux WiFi",        str(len(wifi_nets)))
    t.add_row("Appareils Bluetooth", str(len(bt_devs)))
    t.add_row("Vulnérabilités",      f"[bold red]{len(vulns)}[/bold red]" if vulns else "0")
    console.print(Panel(t, title="[bold]Résumé[/bold]", border_style="green", padding=(1, 4)))
    return {"hosts": all_hosts, "wifi": wifi_nets, "bluetooth": bt_devs, "vulns": vulns}

# ══════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════
def show_menu():
    items = [
        ("1",  "Scan Complet Avancé",       "Tout en une fois : hôtes+ports+HTTP+SSL+SNMP+WiFi+BT+Vulns", "bold cyan"),
        ("2",  "Découverte des Hôtes",       "Appareils actifs + OS + MAC + vendor",                       "green"),
        ("3",  "Scanner Ports TCP",          "Ports ouverts + service + bannière",                          "yellow"),
        ("4",  "Scanner Ports UDP",          "DNS, SNMP, NTP, SSDP, mDNS, DHCP...",                        "yellow"),
        ("5",  "Scanner HTTP/HTTPS",         "Status, server, titre, technologies, headers sécurité",       "green"),
        ("6",  "Scanner SSL/TLS",            "Certificats, expiry, cipher suite, SANs",                     "green"),
        ("7",  "Scanner DNS",                "Records A/AAAA/MX/NS/TXT/CNAME/SOA + AXFR",                  "cyan"),
        ("8",  "Scanner NetBIOS/SMB",        "Noms Windows, groupes de travail",                            "cyan"),
        ("9",  "Scanner SNMP",               "Community strings, sysDescr, sysName",                        "cyan"),
        ("10", "Réseaux WiFi",               "SSID, BSSID, signal, canal, sécurité, vendeur AP",            "blue"),
        ("11", "Appareils Bluetooth",        "BLE + classique, RSSI, type",                                 "magenta"),
        ("12", "Traceroute",                 "Chemin réseau hop-by-hop vers une cible",                     "yellow"),
        ("13", "Géolocalisation IP",         "Pays, ville, ISP, coordonnées",                               "green"),
        ("14", "WHOIS",                      "Registrar, org, dates pour IP/domaine",                       "blue"),
        ("15", "Services mDNS/Zeroconf",     "Imprimantes, Chromecast, AirPlay, SSH...",                    "cyan"),
        ("16", "Statistiques Réseau",        "Bytes in/out, connexions actives, états TCP",                 "dim"),
        ("17", "Vérif. Credentials Défaut",  "Tester FTP/HTTP/MySQL avec passwords par défaut",             "red"),
        ("18", "Analyse Vulnérabilités",     "Versions vulnérables détectées dans les bannières",           "red"),
        ("19", "Interfaces Réseau",          "IP, MAC, masque, IPv6, vendeur",                              "cyan"),
        ("20", "Capture en Direct",          "Paquets réseau temps réel (Npcap/root requis)",               "red"),
        ("0",  "Quitter",                    "",                                                             "dim"),
    ]
    t = Table(box=box.ROUNDED, show_header=False, padding=(0, 1),
              border_style="cyan", width=80)
    t.add_column("", width=5); t.add_column("", min_width=28); t.add_column("", style="dim")
    for key, name, desc, color in items:
        t.add_row(f"[{color}][{key:>2}][/{color}]", f"[{color}]{name}[/{color}]", desc)
    console.print(Panel(t, title="[bold cyan]  NETRADAR v2.0.0 — MENU  [/bold cyan]",
                        border_style="cyan", padding=(1, 2)))

def _ask(prompt: str, default: str = "") -> str:
    try:
        suffix = f" [dim](défaut: {default})[/dim]" if default else ""
        console.print(f"[bold cyan]{prompt}[/bold cyan]{suffix}: ", end="")
        val = input().strip()
        return val or default
    except (EOFError, KeyboardInterrupt):
        return default

def _parse_ports(spec: str) -> List[int]:
    s = spec.strip().lower()
    if s in ("", "common"):
        return COMMON_TCP_PORTS
    if "-" in s and "," not in s:
        try:
            a, b = s.split("-", 1)
            return list(range(int(a), int(b) + 1))
        except ValueError:
            pass
    try:
        return [int(p.strip()) for p in s.split(",") if p.strip()]
    except ValueError:
        return COMMON_TCP_PORTS

def interactive_mode():
    print_banner()
    while True:
        show_menu()
        choice = _ask("\nVotre choix", "1")
        console.print()

        if choice == "0":
            console.print("[bold cyan]Au revoir ![/bold cyan]"); break

        elif choice == "1":
            full_scan()

        elif choice == "2":
            local  = get_local_ip()
            defnet = ".".join(local.split(".")[:3]) + ".0/24"
            net    = _ask("Réseau à scanner", defnet)
            with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]{net}"),
                          BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
                          console=console) as prog:
                task = prog.add_task(net, total=256)
                def cb(d, t, _t=task, _p=prog): _p.update(_t, completed=d, total=t)
                display_hosts(scan_network(net, cb))

        elif choice == "3":
            ip    = _ask("IP cible")
            spec  = _ask("Ports (common / 1-1024 / 80,443)", "common")
            ports = _parse_ports(spec)
            with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]TCP {ip}"),
                          BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
                          console=console) as prog:
                task = prog.add_task("", total=len(ports))
                def pcb(d, t, _t=task, _p=prog): _p.update(_t, completed=d)
                display_ports(ip, scan_ports(ip, ports, pcb))

        elif choice == "4":
            ip = _ask("IP cible")
            with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]UDP {ip}"),
                          console=console) as p:
                p.add_task("", total=None)
                display_udp(ip, scan_udp(ip))

        elif choice == "5":
            ip    = _ask("IP ou hostname")
            port  = int(_ask("Port", "80"))
            https = port in (443, 8443, 4443, 7443, 9443)
            display_http([scan_http(ip, port, https)])

        elif choice == "6":
            ip   = _ask("IP cible")
            port = int(_ask("Port", "443"))
            display_ssl([scan_ssl(ip, port)])

        elif choice == "7":
            target = _ask("Domaine ou IP")
            display_dns(scan_dns(target))

        elif choice == "8":
            ip = _ask("IP cible")
            display_netbios([scan_netbios(ip)])

        elif choice == "9":
            ip = _ask("IP cible")
            display_snmp([scan_snmp(ip)])

        elif choice == "10":
            with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]Scan WiFi..."),
                          console=console) as p:
                p.add_task("", total=None)
                display_wifi(scan_wifi())

        elif choice == "11":
            console.print("[dim]Scan Bluetooth (~8s)...[/dim]")
            with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]Scan BT..."),
                          console=console) as p:
                p.add_task("", total=None)
                display_bluetooth(scan_bluetooth())

        elif choice == "12":
            target = _ask("Cible (IP ou domaine)")
            display_traceroute(target, run_traceroute(target))

        elif choice == "13":
            ip  = _ask("IP à géolocaliser")
            res = geolocate(ip)
            display_geolocate([res])

        elif choice == "14":
            target = _ask("IP ou domaine")
            display_whois(target, whois_lookup(target))

        elif choice == "15":
            console.print("[dim]Scan mDNS (~5s)...[/dim]")
            display_mdns(scan_mdns(5.0))

        elif choice == "16":
            display_netstats(get_net_stats())

        elif choice == "17":
            ip   = _ask("IP cible")
            spec = _ask("Ports (21,80,3306)", "21,80,3306")
            all_f = []
            for port in _parse_ports(spec):
                if port in DEFAULT_CREDS:
                    console.print(f"[dim]Test {ip}:{port}...[/dim]")
                    all_f.extend(check_default_creds(ip, port))
            display_default_creds(all_f)

        elif choice == "18":
            ip    = _ask("IP cible")
            spec  = _ask("Ports", "common")
            ports = _parse_ports(spec)
            with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]TCP {ip}"),
                          BarColumn(bar_width=25), TextColumn("{task.percentage:>3.0f}%"),
                          console=console) as prog:
                task = prog.add_task("", total=len(ports))
                def pcb2(d, t, _t=task, _p=prog): _p.update(_t, completed=d)
                open_p = scan_ports(ip, ports, pcb2)
            display_ports(ip, open_p)
            display_vulns(check_vulns([{"ip": ip, "ports": open_p}]))

        elif choice == "19":
            display_interfaces(get_interfaces())

        elif choice == "20":
            n = int(_ask("Nombre de paquets", "100"))
            live_capture(count=n)

        else:
            console.print("[red]Option invalide.[/red]")

        console.print()
        try:
            input("[dim]Appuyez sur Entrée pour continuer...[/dim]")
        except (EOFError, KeyboardInterrupt):
            pass
        console.clear()
        print_banner()

# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        description="NetRadar v2.0.0 — Advanced Network Intelligence Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python netRadar.py                       Menu interactif (20 options)
  python netRadar.py --full                Scan complet automatique
  python netRadar.py --hosts               Découvrir les hôtes (réseau local)
  python netRadar.py --ports 192.168.1.1   Scanner ports TCP
  python netRadar.py --udp 192.168.1.1     Scanner ports UDP
  python netRadar.py --http 192.168.1.1    Scanner HTTP/HTTPS
  python netRadar.py --ssl 192.168.1.1     Scanner certificat SSL
  python netRadar.py --dns google.com      Records DNS
  python netRadar.py --snmp 192.168.1.1    Scanner SNMP
  python netRadar.py --traceroute 8.8.8.8  Traceroute
  python netRadar.py --geolocate 8.8.8.8   Géolocalisation
  python netRadar.py --whois 8.8.8.8       WHOIS
  python netRadar.py --wifi                Réseaux WiFi
  python netRadar.py --bluetooth           Appareils Bluetooth
  python netRadar.py --mdns                Services mDNS
  python netRadar.py --live --count 200    Capture paquets
        """)
    ap.add_argument("--full",       "-f",  action="store_true")
    ap.add_argument("--interfaces", "-i",  action="store_true")
    ap.add_argument("--hosts",      "-H",  nargs="?", const="auto", metavar="NETWORK")
    ap.add_argument("--ports",      "-p",  metavar="IP")
    ap.add_argument("--port-range",        metavar="RANGE", default="common")
    ap.add_argument("--udp",               metavar="IP")
    ap.add_argument("--http",              metavar="IP")
    ap.add_argument("--ssl",               metavar="IP")
    ap.add_argument("--dns",               metavar="TARGET")
    ap.add_argument("--netbios",           metavar="IP")
    ap.add_argument("--snmp",              metavar="IP")
    ap.add_argument("--traceroute", "-t",  metavar="TARGET")
    ap.add_argument("--geolocate",  "-g",  metavar="IP")
    ap.add_argument("--whois",      "-w",  metavar="TARGET")
    ap.add_argument("--mdns",              action="store_true")
    ap.add_argument("--netstats",          action="store_true")
    ap.add_argument("--wifi",              action="store_true")
    ap.add_argument("--bluetooth",  "-b",  action="store_true")
    ap.add_argument("--live",       "-l",  action="store_true")
    ap.add_argument("--count",      "-c",  type=int, default=100)
    ap.add_argument("--version",    "-v",  action="store_true")
    args = ap.parse_args()

    if len(sys.argv) == 1:
        interactive_mode(); return

    print_banner()

    if args.version:
        console.print(f"NetRadar v{VERSION}"); return
    if args.full:
        full_scan(); return
    if args.interfaces:
        display_interfaces(get_interfaces())
    if args.hosts is not None:
        net = args.hosts
        if net == "auto":
            local = get_local_ip()
            net   = ".".join(local.split(".")[:3]) + ".0/24"
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]{net}"),
                      BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
                      console=console) as prog:
            task = prog.add_task(net, total=256)
            def cb(d, t, _t=task, _p=prog): _p.update(_t, completed=d, total=t)
            display_hosts(scan_network(net, cb))
    if args.ports:
        ports = _parse_ports(args.port_range)
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]TCP {args.ports}"),
                      BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
                      console=console) as prog:
            task = prog.add_task("", total=len(ports))
            def pcb(d, t, _t=task, _p=prog): _p.update(_t, completed=d)
            display_ports(args.ports, scan_ports(args.ports, ports, pcb))
    if args.udp:
        with Progress(SpinnerColumn(style="cyan"), TextColumn(f"[cyan]UDP {args.udp}"),
                      console=console) as p:
            p.add_task("", total=None)
            display_udp(args.udp, scan_udp(args.udp))
    if args.http:
        port  = 443 if tcp_connect(args.http, 443, 1) else 80
        display_http([scan_http(args.http, port, port == 443)])
    if args.ssl:
        display_ssl([scan_ssl(args.ssl)])
    if args.dns:
        display_dns(scan_dns(args.dns))
    if args.netbios:
        display_netbios([scan_netbios(args.netbios)])
    if args.snmp:
        display_snmp([scan_snmp(args.snmp)])
    if args.traceroute:
        display_traceroute(args.traceroute, run_traceroute(args.traceroute))
    if args.geolocate:
        display_geolocate([geolocate(args.geolocate)])
    if args.whois:
        display_whois(args.whois, whois_lookup(args.whois))
    if args.mdns:
        display_mdns(scan_mdns())
    if args.netstats:
        display_netstats(get_net_stats())
    if args.wifi:
        with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]WiFi..."),
                      console=console) as p:
            p.add_task("", total=None)
            display_wifi(scan_wifi())
    if args.bluetooth:
        with Progress(SpinnerColumn(style="cyan"), TextColumn("[cyan]BT..."),
                      console=console) as p:
            p.add_task("", total=None)
            display_bluetooth(scan_bluetooth())
    if args.live:
        live_capture(count=args.count)

if __name__ == "__main__":
    main()
