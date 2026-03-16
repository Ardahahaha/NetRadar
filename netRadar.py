#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
 ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
                  Advanced Network Intelligence Scanner  v1.0.0
"""

import os
import sys

# ── Fix Windows UTF-8 encoding ────────────────────────────────
if sys.platform == "win32":
    import io
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
import struct
import platform
import json
import ctypes
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any

# ══════════════════════════════════════════════════════════════
#  RICH UI  (required)
# ══════════════════════════════════════════════════════════════
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (Progress, SpinnerColumn,
                               TextColumn, BarColumn, TaskProgressColumn)
    from rich.rule import Rule
    from rich import box
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    console = Console(force_terminal=True, highlight=False)
except ImportError:
    print("ERREUR: 'rich' non installé. Lancez: pip install rich")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
#  OPTIONAL LIBRARIES
# ══════════════════════════════════════════════════════════════
try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY = True
except Exception:
    SCAPY = False

try:
    import nmap
    NMAP = True
except Exception:
    NMAP = False

try:
    import netifaces
    NETIFACES = True
except Exception:
    NETIFACES = False

try:
    import pywifi
    from pywifi import const as wconst
    PYWIFI = True
except Exception:
    PYWIFI = False

try:
    from bleak import BleakScanner
    BLEAK = True
except Exception:
    BLEAK = False

try:
    import bluetooth
    PYBT = True
except Exception:
    PYBT = False

# ══════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════
VERSION     = "1.0.0"
IS_WINDOWS  = platform.system() == "Windows"
try:
    IS_ADMIN = bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else os.geteuid() == 0
except Exception:
    IS_ADMIN = False

BANNER = r"""[bold cyan] ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝
 ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
 ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝[/bold cyan]"""

COMMON_PORTS: Dict[int, str] = {
    21: "FTP",      22: "SSH",        23: "Telnet",    25: "SMTP",
    53: "DNS",      80: "HTTP",       110: "POP3",     135: "RPC",
    139: "NetBIOS", 143: "IMAP",      161: "SNMP",     389: "LDAP",
    443: "HTTPS",   445: "SMB",       636: "LDAPS",    993: "IMAPS",
    995: "POP3S",   1433: "MSSQL",    1521: "Oracle",  3306: "MySQL",
    3389: "RDP",    5432: "PostgreSQL",5900: "VNC",     5985: "WinRM",
    6379: "Redis",  8080: "HTTP-Alt", 8443: "HTTPS-Alt",8888: "HTTP-Dev",
    27017: "MongoDB",9200: "Elasticsearch",5601: "Kibana",2375: "Docker",
    2049: "NFS",    111: "RPC-Bind",  123: "NTP",      179: "BGP",
    514: "Syslog",  587: "SMTP-TLS",  631: "IPP",      873: "rsync",
    902: "VMware",  1080: "SOCKS",    1194: "OpenVPN", 1723: "PPTP",
    1883: "MQTT",   2181: "Zookeeper",2222: "SSH-Alt", 4444: "Metasploit",
    4848: "GlassFish",5000: "Flask",  5432: "PostgreSQL",6000: "X11",
    7001: "WebLogic",8009: "AJP",     8161: "ActiveMQ",8888: "Jupyter",
    9000: "SonarQube",9090: "Prometheus",9200: "Elasticsearch",10000: "Webmin",
}

# OUI → Vendor (top manufacturers)
MAC_VENDORS: Dict[str, str] = {
    "00:00:0C": "Cisco",        "00:0A:E4": "Cisco",        "00:1A:2B": "Cisco",
    "00:50:56": "VMware",       "00:0C:29": "VMware",       "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "VirtualBox",   "52:54:00": "QEMU/KVM",     "00:16:3E": "Xen",
    "B4:E6:2D": "Apple",        "F0:18:98": "Apple",        "3C:07:54": "Apple",
    "00:1C:B3": "Apple",        "78:D7:5A": "Apple",        "00:25:00": "Apple",
    "AC:DE:48": "Apple",        "F4:F1:5A": "Apple",        "28:CF:E9": "Apple",
    "00:23:14": "Intel",        "00:1B:21": "Intel",        "78:2B:CB": "Intel",
    "AC:FD:CE": "Intel",        "3C:77:E6": "Intel",        "8C:8D:28": "Intel",
    "00:E0:4C": "Realtek",      "00:26:9E": "Realtek",      "E0:CB:4E": "Realtek",
    "BC:5F:F4": "ASUS",         "00:90:F5": "ASUS",         "1C:6F:65": "ASUS",
    "AC:9E:17": "ASUS",         "04:D4:C4": "ASUS",         "2C:4D:54": "ASUS",
    "F0:9F:C2": "TP-Link",      "50:C7:BF": "TP-Link",      "74:DA:38": "TP-Link",
    "C4:6E:1F": "TP-Link",      "B0:BE:76": "TP-Link",      "30:DE:4B": "TP-Link",
    "00:14:78": "Netgear",      "A0:63:91": "Netgear",      "C4:04:15": "Netgear",
    "28:C6:8E": "Netgear",      "20:E5:2A": "Netgear",      "9C:D3:6D": "Netgear",
    "C8:3A:35": "Tenda",        "CC:B2:55": "Tenda",        "00:26:66": "Tenda",
    "B4:0F:3B": "Huawei",       "00:1E:10": "Huawei",       "00:E0:FC": "Huawei",
    "48:FD:8E": "Huawei",       "A4:50:46": "Huawei",       "70:7B:E8": "Huawei",
    "00:17:88": "Philips Hue",  "EC:B5:FA": "Xiaomi",       "F8:A2:D6": "Xiaomi",
    "28:6C:07": "Xiaomi",       "50:8F:4C": "Xiaomi",       "64:09:80": "Xiaomi",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:0D:3A": "Microsoft",    "28:18:78": "Microsoft",    "00:50:F2": "Microsoft",
    "54:27:1E": "Samsung",      "B8:BC:1B": "Samsung",      "CC:07:AB": "Samsung",
    "00:1D:25": "Samsung",      "84:38:35": "Samsung",      "8C:77:12": "Samsung",
    "00:1E:C2": "Dell",         "14:FE:B5": "Dell",         "00:22:19": "Dell",
    "00:14:22": "Dell",         "18:03:73": "Dell",         "F8:DB:88": "Dell",
    "00:24:E8": "HP",           "D8:D3:85": "HP",           "C4:34:6B": "HP",
    "68:B5:99": "HP",           "A0:B3:CC": "HP",           "3C:D9:2B": "HP",
    "00:1A:A0": "D-Link",       "14:D6:4D": "D-Link",       "B0:C5:54": "D-Link",
    "1C:7E:E5": "D-Link",       "90:F6:52": "D-Link",
    "5C:26:0A": "ASRock",       "00:11:32": "Synology",     "00:11:62": "QNAP",
    "00:90:A9": "Western Digital","00:50:43": "Zyxel",      "00:A0:C5": "Zyxel",
}

TTL_OS: Dict[Tuple[int, int], str] = {
    (1,  64):  "Linux / Android / macOS",
    (65, 128): "Windows",
    (129, 255): "Network Device (Cisco / HP / Juniper)",
}


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def run_cmd(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore")
        return r.stdout + r.stderr
    except Exception:
        return ""


def get_mac_vendor(mac: str) -> str:
    if not mac or mac in ("N/A", ""):
        return "Unknown"
    norm = mac.upper().replace("-", ":")
    return (MAC_VENDORS.get(norm[:8]) or
            MAC_VENDORS.get(norm[:5]) or
            "Unknown")


def guess_os_from_ttl(ttl: int) -> str:
    for (lo, hi), name in TTL_OS.items():
        if lo <= ttl <= hi:
            return name
    return "Unknown"


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def signal_bar(pct: int) -> str:
    """Return a 5-block signal bar string."""
    filled = round(pct / 20)
    bar = "█" * filled + "░" * (5 - filled)
    if pct >= 70:
        return f"[green]{bar}[/green]"
    elif pct >= 40:
        return f"[yellow]{bar}[/yellow]"
    return f"[red]{bar}[/red]"


# ══════════════════════════════════════════════════════════════
#  NETWORK INTERFACES
# ══════════════════════════════════════════════════════════════
def get_interfaces() -> List[Dict]:
    """Return all network interfaces with IPv4, IPv6, MAC."""
    interfaces: List[Dict] = []

    if NETIFACES:
        for name in netifaces.interfaces():
            entry: Dict = {"name": name, "ipv4": [], "ipv6": [], "mac": "N/A"}
            addrs = netifaces.ifaddresses(name)
            if netifaces.AF_INET in addrs:
                for a in addrs[netifaces.AF_INET]:
                    entry["ipv4"].append({
                        "ip":        a.get("addr", ""),
                        "netmask":   a.get("netmask", ""),
                        "broadcast": a.get("broadcast", ""),
                    })
            if netifaces.AF_INET6 in addrs:
                entry["ipv6"] = [a.get("addr", "") for a in addrs[netifaces.AF_INET6]]
            if netifaces.AF_LINK in addrs:
                entry["mac"] = addrs[netifaces.AF_LINK][0].get("addr", "N/A").upper()
            if entry["ipv4"] or entry["mac"] != "N/A":
                interfaces.append(entry)
        return interfaces

    # ── Fallback: ipconfig /all (Windows, multilingual) ────
    if IS_WINDOWS:
        out = run_cmd("ipconfig /all")
        cur: Optional[Dict] = None

        # Keywords that indicate it's a real IPv4 address line
        # (handles both English and French and other locales)
        IPV4_HINTS = re.compile(
            r"ipv4|ip address|adresse ipv4|adresse ip", re.I)
        # Keywords for subnet mask (language-agnostic: just look for "masque" or "mask")
        MASK_HINTS = re.compile(
            r"subnet.mask|masque|netzmaske|subnetmask", re.I)
        # Keywords for physical / MAC address
        MAC_HINTS  = re.compile(
            r"physical address|adresse physique|mac address", re.I)
        # Keywords for IPv6
        IPV6_HINTS = re.compile(r"ipv6|lien.local", re.I)

        for raw in out.splitlines():
            line = raw.strip()
            # Adapter header: no leading spaces, ends with ':' or ' :'
            if raw and not raw.startswith(" ") and line.endswith(":"):
                # Skip the global "Windows IP Configuration" header
                if re.search(r"configuration ip|ip configuration", line, re.I):
                    continue
                if cur:
                    interfaces.append(cur)
                name = re.sub(r"\s*:$", "", line).strip()
                cur = {"name": name, "ipv4": [], "ipv6": [], "mac": "N/A"}
            elif cur:
                # MAC address (exactly 6 octets separated by - or :)
                if MAC_HINTS.search(line):
                    m = re.search(
                        r"\b([0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}"
                        r"[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2}[-][0-9A-Fa-f]{2})\b",
                        line)
                    if m:
                        cur["mac"] = m.group(1).replace("-", ":").upper()
                # IPv4 address (strip Windows locale suffixes like (Preferred)/(prfr))
                elif IPV4_HINTS.search(line):
                    clean = re.sub(r"\(.*?\)", "", line)
                    m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", clean)
                    if m and not m.group(1).startswith("169.254"):
                        cur["ipv4"].append(
                            {"ip": m.group(1), "netmask": "", "broadcast": ""})
                # Subnet mask (255.x.x.x)
                elif MASK_HINTS.search(line):
                    m = re.search(r"(255\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if m and cur["ipv4"]:
                        cur["ipv4"][-1]["netmask"] = m.group(1)
                # IPv6
                elif IPV6_HINTS.search(line):
                    m = re.search(r"([0-9a-fA-F]{1,4}:[0-9a-fA-F:]+)", line)
                    if m:
                        addr = m.group(1).rstrip(":")
                        # Strip zone ID like %30
                        addr = re.sub(r"%\d+", "", addr)
                        cur["ipv6"].append(addr)
        if cur:
            interfaces.append(cur)
    else:
        # Linux fallback: ip addr show
        out = run_cmd("ip addr show")
        cur = None
        for line in out.splitlines():
            line = line.strip()
            m = re.match(r"^\d+:\s+(\S+):", line)
            if m:
                if cur:
                    interfaces.append(cur)
                cur = {"name": m.group(1), "ipv4": [], "ipv6": [], "mac": "N/A"}
            elif cur:
                m4 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+brd\s+(\S+))?", line)
                if m4:
                    cur["ipv4"].append({
                        "ip": m4.group(1),
                        "netmask": str(ipaddress.IPv4Network(f"0.0.0.0/{m4.group(2)}").netmask),
                        "broadcast": m4.group(3) or "",
                    })
                m6 = re.search(r"inet6 ([0-9a-fA-F:]+/\d+)", line)
                if m6:
                    cur["ipv6"].append(m6.group(1))
                mm = re.search(r"link/ether\s+([0-9a-fA-F:]+)", line)
                if mm:
                    cur["mac"] = mm.group(1).upper()
        if cur:
            interfaces.append(cur)

    return [i for i in interfaces if i["ipv4"] or i["mac"] != "N/A"]


def display_interfaces(interfaces: List[Dict]):
    t = Table(
        title="[bold cyan]Network Interfaces[/bold cyan]",
        box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True,
    )
    t.add_column("Interface",  style="bold cyan",  no_wrap=True, min_width=18)
    t.add_column("IPv4 Address", style="green",    min_width=15)
    t.add_column("Subnet Mask",  style="yellow",   min_width=15)
    t.add_column("Broadcast",    style="dim",      min_width=15)
    t.add_column("MAC Address",  style="red",      min_width=17)
    t.add_column("Vendor",       style="blue")
    t.add_column("IPv6",         style="dim",      min_width=20)

    for iface in interfaces:
        mac    = iface.get("mac", "N/A")
        vendor = get_mac_vendor(mac)
        ipv6s  = ", ".join(iface.get("ipv6", [])[:2])
        rows   = iface.get("ipv4", [{"ip": "", "netmask": "", "broadcast": ""}])
        for i, addr in enumerate(rows):
            t.add_row(
                iface["name"] if i == 0 else "",
                addr.get("ip", ""),
                addr.get("netmask", ""),
                addr.get("broadcast", ""),
                mac    if i == 0 else "",
                vendor if i == 0 else "",
                ipv6s  if i == 0 else "",
            )
    console.print(t)


# ══════════════════════════════════════════════════════════════
#  HOST DISCOVERY
# ══════════════════════════════════════════════════════════════
def ping_host(ip: str) -> Tuple[bool, int]:
    cmd = (f"ping -n 1 -w 500 {ip}" if IS_WINDOWS
           else f"ping -c 1 -W 1 {ip}")
    out = run_cmd(cmd, timeout=4)
    alive = bool(re.search(r"TTL=\d+", out, re.I))
    ttl_m = re.search(r"TTL=(\d+)", out, re.I)
    ttl   = int(ttl_m.group(1)) if ttl_m else 64
    return alive, ttl


def get_arp_table() -> Dict[str, str]:
    arp: Dict[str, str] = {}
    out = run_cmd("arp -a")
    for line in out.splitlines():
        if IS_WINDOWS:
            m = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
                r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                line)
        else:
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
        if m:
            ip  = m.group(1)
            mac = m.group(2).replace("-", ":").upper()
            if not ip.endswith(".255") and not ip.startswith("224."):
                arp[ip] = mac
    return arp


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_network(network: str,
                 progress_cb=None) -> List[Dict]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []

    all_ips  = [str(ip) for ip in list(net.hosts())[:512]]
    alive    : List[str]     = []
    ttl_map  : Dict[str, int]= {}
    lock     = threading.Lock()

    def worker(ip: str) -> Tuple[str, bool, int]:
        ok, ttl = ping_host(ip)
        return ip, ok, ttl

    completed = 0
    with ThreadPoolExecutor(max_workers=80) as ex:
        futs = {ex.submit(worker, ip): ip for ip in all_ips}
        for fut in as_completed(futs):
            ip, ok, ttl = fut.result()
            if ok:
                with lock:
                    alive.append(ip)
                    ttl_map[ip] = ttl
            completed += 1
            if progress_cb:
                progress_cb(completed, len(all_ips))

    arp = get_arp_table()
    hosts: List[Dict] = []
    for ip in sorted(alive, key=lambda x: [int(p) for p in x.split(".")]):
        mac  = arp.get(ip, "N/A")
        ttl  = ttl_map.get(ip, 64)
        hosts.append({
            "ip":       ip,
            "mac":      mac,
            "vendor":   get_mac_vendor(mac),
            "hostname": resolve_hostname(ip),
            "ttl":      ttl,
            "os":       guess_os_from_ttl(ttl),
            "ports":    [],
        })
    return hosts


def display_hosts(hosts: List[Dict]):
    if not hosts:
        console.print("[yellow]Aucun hôte découvert.[/yellow]")
        return
    t = Table(
        title=f"[bold cyan]Hôtes Découverts — {len(hosts)} trouvé(s)[/bold cyan]",
        box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True,
    )
    t.add_column("#",          style="dim",  width=4)
    t.add_column("IP Address", style="bold cyan",  no_wrap=True, min_width=15)
    t.add_column("Hostname",   style="green",       min_width=20)
    t.add_column("MAC Address",style="red",         min_width=17)
    t.add_column("Vendor",     style="blue")
    t.add_column("TTL",        style="yellow", width=6)
    t.add_column("OS (guess)", style="magenta")

    for i, h in enumerate(hosts, 1):
        os_name  = h.get("os", "Unknown")
        os_color = ("cyan"   if "Windows" in os_name else
                    "green"  if "Linux"   in os_name else
                    "yellow")
        t.add_row(
            str(i),
            h["ip"],
            h.get("hostname", "") or "[dim]N/A[/dim]",
            h["mac"],
            h["vendor"],
            str(h["ttl"]),
            f"[{os_color}]{os_name}[/{os_color}]",
        )
    console.print(t)


# ══════════════════════════════════════════════════════════════
#  PORT SCANNER
# ══════════════════════════════════════════════════════════════
def scan_port(ip: str, port: int, timeout: float = 0.7) -> bool:
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
        s.settimeout(1.5)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner.splitlines()[0][:60] if banner else ""
    except Exception:
        return ""


def scan_ports(ip: str,
               ports: Optional[List[int]] = None,
               progress_cb=None) -> List[Dict]:
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports: List[Dict] = []
    completed  = 0

    def worker(port: int) -> Tuple[int, bool]:
        return port, scan_port(ip, port)

    with ThreadPoolExecutor(max_workers=120) as ex:
        futs = {ex.submit(worker, p): p for p in ports}
        for fut in as_completed(futs):
            port, ok = fut.result()
            if ok:
                service = COMMON_PORTS.get(port, "Unknown")
                banner  = grab_banner(ip, port)
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "banner":  banner,
                    "state":   "open",
                })
            completed += 1
            if progress_cb:
                progress_cb(completed, len(ports))

    return sorted(open_ports, key=lambda x: x["port"])


def display_ports(ip: str, ports: List[Dict]):
    if not ports:
        console.print(f"[yellow]Aucun port ouvert sur {ip}[/yellow]")
        return
    t = Table(
        title=f"[bold cyan]Ports Ouverts — {ip}  ({len(ports)} trouvé(s))[/bold cyan]",
        box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True,
    )
    t.add_column("Port",    style="bold cyan", width=8)
    t.add_column("État",    style="green",     width=8)
    t.add_column("Service", style="yellow")
    t.add_column("Banner",  style="dim")

    for p in ports:
        t.add_row(
            str(p["port"]),
            "[bold green]OPEN[/bold green]",
            p["service"],
            p.get("banner", ""),
        )
    console.print(t)


# ══════════════════════════════════════════════════════════════
#  WIFI SCANNER
# ══════════════════════════════════════════════════════════════
def _wifi_netsh() -> List[Dict]:
    """Windows: parse netsh wlan show networks mode=bssid"""
    nets: List[Dict] = []
    out = run_cmd("netsh wlan show networks mode=bssid", timeout=20)
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

        m_bssid = re.match(r"^BSSID\s+\d+\s*:\s*(.+)", line, re.I)
        if m_bssid:
            cur["bssid"] = m_bssid.group(1).strip().upper()
            continue

        m_sig = re.search(r"Signal\s*:\s*(\d+)%", line)
        if m_sig:
            pct = int(m_sig.group(1))
            cur["signal_pct"] = pct
            cur["signal_dbm"] = f"{(pct / 2) - 100:.0f} dBm"
            continue

        m_auth = re.search(r"Authentication\s*:\s*(.*)", line)
        if m_auth:
            cur["auth"] = m_auth.group(1).strip()
            continue

        m_enc = re.search(r"Encryption\s*:\s*(.*)", line)
        if m_enc:
            cur["cipher"] = m_enc.group(1).strip()
            continue

        m_ch = re.search(r"Channel\s*:\s*(\d+)", line)
        if m_ch:
            cur["channel"] = m_ch.group(1)
            continue

        m_rt = re.search(r"Radio type\s*:\s*(.*)", line)
        if m_rt:
            cur["radio"] = m_rt.group(1).strip()
            continue

        m_nt = re.search(r"Network type\s*:\s*(.*)", line)
        if m_nt:
            cur["type"] = m_nt.group(1).strip()

    if cur.get("ssid") is not None:
        nets.append(cur)
    return nets


def _wifi_pywifi() -> List[Dict]:
    nets: List[Dict] = []
    try:
        wifi  = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        for r in iface.scan_results():
            akm    = r.akm[0] if r.akm else 0
            auth_m = {wconst.AKM_TYPE_NONE: "Open",
                      wconst.AKM_TYPE_WPA:  "WPA",
                      wconst.AKM_TYPE_WPAPSK: "WPA-PSK",
                      wconst.AKM_TYPE_WPA2:   "WPA2",
                      wconst.AKM_TYPE_WPA2PSK: "WPA2-PSK"}
            pct = min(100, max(0, 2 * (r.signal + 100)))
            nets.append({
                "ssid":       r.ssid or "[Caché]",
                "bssid":      (r.bssid or "N/A").upper(),
                "signal_dbm": f"{r.signal} dBm",
                "signal_pct": pct,
                "auth":       auth_m.get(akm, "Unknown"),
                "channel":    str(getattr(r, "freq", "N/A")),
                "type":       "Infrastructure",
            })
    except Exception:
        pass
    return nets


def scan_wifi() -> List[Dict]:
    if PYWIFI:
        nets = _wifi_pywifi()
        if nets:
            return nets
    if IS_WINDOWS:
        return _wifi_netsh()
    # Linux: nmcli
    out = run_cmd("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY,CHAN dev wifi list")
    nets: List[Dict] = []
    for line in out.strip().splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 4:
            pct = int(parts[2]) if parts[2].isdigit() else 0
            nets.append({
                "ssid":       parts[0].replace("\\:", ":") or "[Caché]",
                "bssid":      parts[1].replace("\\:", ":").upper(),
                "signal_pct": pct,
                "signal_dbm": f"{pct // 2 - 100} dBm",
                "auth":       parts[3],
                "channel":    parts[4] if len(parts) > 4 else "N/A",
                "type":       "Infrastructure",
            })
    return nets


def display_wifi(networks: List[Dict]):
    if not networks:
        console.print("[yellow]Aucun réseau WiFi trouvé. Vérifiez que le WiFi est activé.[/yellow]")
        return

    networks.sort(key=lambda x: x.get("signal_pct", 0), reverse=True)

    t = Table(
        title=f"[bold cyan]Réseaux WiFi — {len(networks)} trouvé(s)[/bold cyan]",
        box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True,
    )
    t.add_column("SSID",           style="bold cyan",  min_width=20)
    t.add_column("BSSID (MAC)",    style="red",        min_width=17)
    t.add_column("Signal",         style="yellow",     width=12)
    t.add_column("Force",          min_width=12)
    t.add_column("Canal",          style="blue",       width=7)
    t.add_column("Sécurité",       min_width=12)
    t.add_column("Radio",          style="dim",        width=12)
    t.add_column("Vendeur AP",     style="blue")

    for net in networks:
        pct    = net.get("signal_pct", 0)
        auth   = net.get("auth", "Unknown")
        bssid  = net.get("bssid", "N/A")
        sec_c  = "red" if auth in ("Open", "None", "") else "green"

        t.add_row(
            net.get("ssid", "[Caché]"),
            bssid,
            net.get("signal_dbm", "N/A"),
            f"{signal_bar(pct)} {pct}%",
            str(net.get("channel", "N/A")),
            f"[{sec_c}]{auth}[/{sec_c}]",
            net.get("radio", "N/A"),
            get_mac_vendor(bssid),
        )
    console.print(t)


# ══════════════════════════════════════════════════════════════
#  BLUETOOTH SCANNER
# ══════════════════════════════════════════════════════════════
async def _ble_scan(timeout: float = 8.0) -> List[Dict]:
    devs: List[Dict] = []
    try:
        discovered = await BleakScanner.discover(timeout=timeout)
        for d in discovered:
            devs.append({
                "name":    d.name or "[Inconnu]",
                "address": d.address.upper(),
                "rssi":    d.rssi,
                "type":    "BLE",
                "status":  "Découvert",
            })
    except Exception:
        pass
    return devs


def _bt_classic() -> List[Dict]:
    devs: List[Dict] = []
    try:
        nearby = bluetooth.discover_devices(duration=8,
                                            lookup_names=True,
                                            lookup_class=True)
        for addr, name, cls in nearby:
            devs.append({
                "name":    name or "[Inconnu]",
                "address": addr.upper(),
                "rssi":    "N/A",
                "type":    "BT Classique",
                "status":  "Découvert",
            })
    except Exception:
        pass
    return devs


def _bt_powershell() -> List[Dict]:
    """Windows fallback using PowerShell."""
    devs: List[Dict] = []
    cmd = ('powershell -Command "Get-PnpDevice -Class Bluetooth | '
           'Select-Object FriendlyName, DeviceID, Status | ConvertTo-Json"')
    out = run_cmd(cmd, timeout=20)
    if not out.strip():
        return devs
    try:
        raw = json.loads(out.strip())
        if isinstance(raw, dict):
            raw = [raw]
        for item in raw:
            if not isinstance(item, dict):
                continue
            name   = item.get("FriendlyName", "Unknown") or "Unknown"
            dev_id = item.get("DeviceID", "")
            status = item.get("Status", "N/A") or "N/A"
            # Try to find a 12-hex-char MAC in the DeviceID
            clean  = re.sub(r"[^0-9A-Fa-f]", "", dev_id)
            mac    = "N/A"
            if len(clean) >= 12:
                raw_mac = clean[:12]
                mac = ":".join(raw_mac[i:i+2] for i in range(0, 12, 2)).upper()
            devs.append({
                "name":    name,
                "address": mac,
                "rssi":    "N/A",
                "type":    "BT/BLE",
                "status":  status,
            })
    except Exception:
        pass
    return devs


def scan_bluetooth() -> List[Dict]:
    devs: List[Dict] = []

    if BLEAK:
        import asyncio
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ble = loop.run_until_complete(_ble_scan())
            loop.close()
            devs.extend(ble)
        except Exception:
            pass

    if PYBT:
        known = {d["address"] for d in devs}
        for d in _bt_classic():
            if d["address"] not in known:
                devs.append(d)

    if not devs and IS_WINDOWS:
        devs.extend(_bt_powershell())

    return devs


def display_bluetooth(devices: List[Dict]):
    if not devices:
        console.print("[yellow]Aucun appareil Bluetooth trouvé. "
                      "Vérifiez que le Bluetooth est activé.[/yellow]")
        return
    t = Table(
        title=f"[bold cyan]Appareils Bluetooth — {len(devices)} trouvé(s)[/bold cyan]",
        box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True,
    )
    t.add_column("Nom",           style="bold cyan",  min_width=22)
    t.add_column("Adresse MAC",   style="red",        min_width=17)
    t.add_column("RSSI",          style="yellow",     width=12)
    t.add_column("Type",          style="green")
    t.add_column("Statut",        style="blue")

    for dev in devices:
        rssi = dev.get("rssi", "N/A")
        if isinstance(rssi, int):
            color  = ("green"  if rssi >= -70 else
                      "yellow" if rssi >= -90 else "red")
            rssi_s = f"[{color}]{rssi} dBm[/{color}]"
        else:
            rssi_s = str(rssi)
        t.add_row(
            dev.get("name", "[Inconnu]"),
            dev.get("address", "N/A"),
            rssi_s,
            dev.get("type", "N/A"),
            dev.get("status", "N/A"),
        )
    console.print(t)


# ══════════════════════════════════════════════════════════════
#  LIVE PACKET CAPTURE
# ══════════════════════════════════════════════════════════════
def live_capture(interface: Optional[str] = None, count: int = 100):
    if not SCAPY:
        console.print("[red]Scapy non disponible. Installez-le: pip install scapy[/red]")
        if IS_WINDOWS:
            console.print("[yellow]Installez aussi Npcap depuis npcap.com[/yellow]")
        return

    console.print(Rule("[bold cyan]CAPTURE EN DIRECT[/bold cyan]", style="cyan"))
    console.print(
        f"[dim]Interface: {interface or 'auto'} | Paquets max: {count} | "
        f"[bold]Ctrl+C[/bold] pour arrêter[/dim]\n"
    )
    # Header
    console.print(
        f"[bold dim]{'#':>5}  {'Heure':12}  {'Src IP':15}  {'Dst IP':15}  "
        f"{'Proto':8}  {'Src MAC':17}  Info[/bold dim]"
    )
    console.print("[dim]" + "─" * 110 + "[/dim]")

    received = [0]

    def pkt_cb(pkt):
        received[0] += 1
        try:
            ts      = datetime.now().strftime("%H:%M:%S.%f")[:12]
            src_ip  = dst_ip = proto = src_mac = info = ""

            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.upper()

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    sp    = pkt[TCP].sport
                    dp    = pkt[TCP].dport
                    flags = str(pkt[TCP].flags)
                    svc   = COMMON_PORTS.get(dp, COMMON_PORTS.get(sp, ""))
                    info  = (f"{sp} → {dp} [{flags}]"
                             + (f" ({svc})" if svc else ""))
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    sp    = pkt[UDP].sport
                    dp    = pkt[UDP].dport
                    svc   = COMMON_PORTS.get(dp, COMMON_PORTS.get(sp, ""))
                    info  = f"{sp} → {dp}" + (f" ({svc})" if svc else "")
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
                    types = {0: "Echo Reply", 3: "Unreachable",
                             8: "Echo Request", 11: "TTL Exceeded"}
                    info  = types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
                else:
                    proto = f"IP/{pkt[IP].proto}"

            elif pkt.haslayer(ARP):
                proto  = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                src_mac = pkt[ARP].hwsrc.upper()
                info   = "Who has?" if pkt[ARP].op == 1 else "Is at"

            if src_ip or proto:
                console.print(
                    f"[dim]{received[0]:>5}[/dim]  [dim]{ts}[/dim]  "
                    f"[cyan]{src_ip or 'N/A':15}[/cyan]  "
                    f"[red]{dst_ip or 'N/A':15}[/red]  "
                    f"[yellow]{proto or 'N/A':8}[/yellow]  "
                    f"[green]{src_mac or 'N/A':17}[/green]  "
                    f"[dim]{info}[/dim]"
                )
        except Exception:
            pass
        if received[0] >= count:
            return True

    try:
        scapy.sniff(iface=interface, prn=pkt_cb, count=count, store=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]Erreur de capture: {e}[/red]")
        if IS_WINDOWS:
            console.print("[yellow]Assurez-vous que Npcap est installé "
                          "et lancez en tant qu'Administrateur.[/yellow]")

    console.print(f"\n[green]{received[0]} paquets capturés.[/green]")


# ══════════════════════════════════════════════════════════════
#  FULL SCAN
# ══════════════════════════════════════════════════════════════
def _auto_networks(interfaces: List[Dict]) -> List[str]:
    nets: List[str] = []
    for iface in interfaces:
        for addr in iface.get("ipv4", []):
            ip   = addr.get("ip", "")
            mask = addr.get("netmask", "")
            if ip and mask and not ip.startswith("127.") and not ip.startswith("169.254."):
                try:
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    if net.prefixlen >= 16:
                        nets.append(str(net))
                except Exception:
                    pass
    if not nets:
        local = get_local_ip()
        nets.append(".".join(local.split(".")[:3]) + ".0/24")
    return nets


def full_scan() -> Dict:
    console.print(Rule("[bold cyan]  NETRADAR — SCAN COMPLET  [/bold cyan]", style="cyan"))

    # ── 1. Interfaces ─────────────────────────────────────────
    console.print("\n[bold yellow][ 1/5 ]  Interfaces Réseau[/bold yellow]")
    interfaces = get_interfaces()
    display_interfaces(interfaces)
    networks   = _auto_networks(interfaces)

    # ── 2. Host Discovery ─────────────────────────────────────
    console.print(f"\n[bold yellow][ 2/5 ]  Découverte des Hôtes — "
                  f"{', '.join(networks)}[/bold yellow]")
    all_hosts: List[Dict] = []
    for net in networks:
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn(f"[cyan]Scan {net}..."),
                      BarColumn(bar_width=35),
                      TaskProgressColumn(),
                      console=console) as prog:
            task = prog.add_task(net, total=256)
            def cb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d, total=t)
            hosts = scan_network(net, cb)
            all_hosts.extend(hosts)
    display_hosts(all_hosts)

    # ── 3. Port Scan (first 15 hosts) ─────────────────────────
    console.print(f"\n[bold yellow][ 3/5 ]  Scan des Ports[/bold yellow]")
    for host in all_hosts[:15]:
        ip = host["ip"]
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn(f"[cyan]Ports → {ip}"),
                      BarColumn(bar_width=35),
                      TaskProgressColumn(),
                      console=console) as prog:
            task = prog.add_task(ip, total=len(COMMON_PORTS))
            def pcb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d)
            open_p = scan_ports(ip, progress_cb=pcb)
            host["ports"] = open_p
        display_ports(ip, open_p)

    # ── 4. WiFi ───────────────────────────────────────────────
    console.print("\n[bold yellow][ 4/5 ]  Réseaux WiFi[/bold yellow]")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[cyan]Scan WiFi..."),
                  console=console) as prog:
        prog.add_task("wifi", total=None)
        wifi_nets = scan_wifi()
    display_wifi(wifi_nets)

    # ── 5. Bluetooth ──────────────────────────────────────────
    console.print("\n[bold yellow][ 5/5 ]  Appareils Bluetooth[/bold yellow]")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[cyan]Scan Bluetooth (~10s)..."),
                  console=console) as prog:
        prog.add_task("bt", total=None)
        bt_devs = scan_bluetooth()
    display_bluetooth(bt_devs)

    # ── Summary ───────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold green]  SCAN TERMINÉ  [/bold green]", style="green"))

    summary = Table(box=box.ROUNDED, show_header=False,
                    padding=(0, 3), border_style="green")
    summary.add_column("Item",  style="bold")
    summary.add_column("Count", style="bold cyan")
    summary.add_row("Interfaces réseau",   str(len(interfaces)))
    summary.add_row("Hôtes découverts",    str(len(all_hosts)))
    summary.add_row("Ports ouverts (tot)", str(sum(len(h["ports"]) for h in all_hosts)))
    summary.add_row("Réseaux WiFi",        str(len(wifi_nets)))
    summary.add_row("Appareils Bluetooth", str(len(bt_devs)))

    console.print(Panel(summary, title="[bold]Résumé[/bold]",
                        border_style="green", padding=(1, 4)))

    return {
        "interfaces":  interfaces,
        "hosts":       all_hosts,
        "wifi":        wifi_nets,
        "bluetooth":   bt_devs,
        "timestamp":   datetime.now().isoformat(),
    }


# ══════════════════════════════════════════════════════════════
#  BANNER & MENU
# ══════════════════════════════════════════════════════════════
def print_banner():
    console.print(BANNER)
    admin_s  = "[bold green]Oui[/bold green]" if IS_ADMIN else "[bold red]Non[/bold red]"
    platform_s = f"{platform.system()} {platform.release()}"
    mods: List[str] = []
    for name, flag in [("scapy", SCAPY), ("nmap", NMAP), ("pywifi", PYWIFI),
                       ("bleak", BLEAK),  ("pybluez", PYBT), ("netifaces", NETIFACES)]:
        color = "green" if flag else "red"
        mods.append(f"[{color}]{name}[/{color}]")

    console.print(
        f"  [bold white]NetRadar[/bold white] [dim]v{VERSION}[/dim]  │  "
        f"[dim]{platform_s}[/dim]  │  "
        f"Admin: {admin_s}  │  "
        f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
    )
    console.print(f"  Modules: {' '.join(mods)}\n")


def show_menu():
    items = [
        ("1", "Scan Complet",            "Interfaces + hôtes + ports + WiFi + Bluetooth",  "bold cyan"),
        ("2", "Découvrir les Hôtes",     "Trouver tous les appareils sur le réseau",       "green"),
        ("3", "Scanner les Ports",       "Ports ouverts sur une IP cible",                 "yellow"),
        ("4", "Réseaux WiFi",            "Voir tous les réseaux WiFi à proximité",         "blue"),
        ("5", "Appareils Bluetooth",     "Scanner les appareils BT/BLE proches",           "magenta"),
        ("6", "Interfaces Réseau",       "IP, MAC, masque de sous-réseau, vendeur",        "cyan"),
        ("7", "Capture en Direct",       "Afficher les paquets réseau en temps réel",      "red"),
        ("0", "Quitter",                  "",                                               "dim"),
    ]
    t = Table(box=box.ROUNDED, show_header=False,
              padding=(0, 2), border_style="cyan", width=72)
    t.add_column("Touche", width=6)
    t.add_column("Option",      min_width=25)
    t.add_column("Description", style="dim")
    for key, name, desc, color in items:
        t.add_row(
            f"[{color}][ {key} ][/{color}]",
            f"[{color}]{name}[/{color}]",
            desc,
        )
    console.print(Panel(t, title="[bold cyan]  NETRADAR MENU  [/bold cyan]",
                        border_style="cyan", padding=(1, 2)))


# ══════════════════════════════════════════════════════════════
#  INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════
def interactive_mode():
    print_banner()
    while True:
        show_menu()
        choice = Prompt.ask("\n[bold cyan]Votre choix[/bold cyan]", default="1")
        console.print()

        if choice == "0":
            console.print("[bold cyan]Au revoir ! Restez sécurisé en ligne.[/bold cyan]")
            break

        elif choice == "1":
            full_scan()

        elif choice == "2":
            local  = get_local_ip()
            defnet = ".".join(local.split(".")[:3]) + ".0/24"
            net    = Prompt.ask("[cyan]Réseau à scanner[/cyan]", default=defnet)
            with Progress(SpinnerColumn(style="cyan"),
                          TextColumn(f"[cyan]Scan {net}..."),
                          BarColumn(bar_width=35),
                          TaskProgressColumn(),
                          console=console) as prog:
                task = prog.add_task(net, total=256)
                def cb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d, total=t)
                hosts = scan_network(net, cb)
            display_hosts(hosts)

        elif choice == "3":
            ip         = Prompt.ask("[cyan]IP cible[/cyan]")
            port_input = Prompt.ask("[cyan]Ports (common / 1-1024 / 80,443,8080)[/cyan]",
                                    default="common")
            ports = _parse_ports(port_input)
            with Progress(SpinnerColumn(style="cyan"),
                          TextColumn(f"[cyan]Scan ports {ip}..."),
                          BarColumn(bar_width=35),
                          TaskProgressColumn(),
                          console=console) as prog:
                task = prog.add_task(ip, total=len(ports))
                def pcb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d)
                open_p = scan_ports(ip, ports, pcb)
            display_ports(ip, open_p)

        elif choice == "4":
            with Progress(SpinnerColumn(style="cyan"),
                          TextColumn("[cyan]Scan WiFi..."),
                          console=console) as prog:
                prog.add_task("wifi", total=None)
                nets = scan_wifi()
            display_wifi(nets)

        elif choice == "5":
            console.print("[dim]Scan Bluetooth en cours (~10 secondes)...[/dim]")
            with Progress(SpinnerColumn(style="cyan"),
                          TextColumn("[cyan]Scan Bluetooth..."),
                          console=console) as prog:
                prog.add_task("bt", total=None)
                devs = scan_bluetooth()
            display_bluetooth(devs)

        elif choice == "6":
            display_interfaces(get_interfaces())

        elif choice == "7":
            n = int(Prompt.ask("[cyan]Nombre de paquets à capturer[/cyan]",
                               default="100"))
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
#  PORT RANGE PARSER
# ══════════════════════════════════════════════════════════════
def _parse_ports(spec: str) -> List[int]:
    spec = spec.strip().lower()
    if spec == "common":
        return list(COMMON_PORTS.keys())
    if "-" in spec and "," not in spec:
        try:
            a, b = spec.split("-", 1)
            return list(range(int(a), int(b) + 1))
        except ValueError:
            pass
    try:
        return [int(p.strip()) for p in spec.split(",") if p.strip()]
    except ValueError:
        return list(COMMON_PORTS.keys())


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="NetRadar — Advanced Network Intelligence Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python netRadar.py                       Mode interactif (menu)
  python netRadar.py --full                Scan complet
  python netRadar.py --interfaces          Afficher les interfaces
  python netRadar.py --hosts               Découvrir les hôtes (réseau local)
  python netRadar.py --hosts 10.0.0.0/24   Découvrir les hôtes (réseau spécifique)
  python netRadar.py --ports 192.168.1.1   Scanner les ports d'une IP
  python netRadar.py --port-range 1-1024   Plage de ports personnalisée
  python netRadar.py --wifi                Scanner les réseaux WiFi
  python netRadar.py --bluetooth           Scanner les appareils Bluetooth
  python netRadar.py --live                Capture de paquets en direct
  python netRadar.py --live --count 200    Capturer 200 paquets
        """
    )
    parser.add_argument("--full",        "-f",  action="store_true",
                        help="Scan complet du réseau")
    parser.add_argument("--interfaces",  "-i",  action="store_true",
                        help="Afficher les interfaces réseau")
    parser.add_argument("--hosts",       "-H",  nargs="?", const="auto",
                        metavar="NETWORK",
                        help="Découvrir les hôtes (ex: 192.168.1.0/24)")
    parser.add_argument("--ports",       "-p",  metavar="IP",
                        help="Scanner les ports d'une IP")
    parser.add_argument("--port-range",  metavar="RANGE", default="common",
                        help="Plage: 'common', '1-1024', '80,443'")
    parser.add_argument("--wifi",        "-w",  action="store_true",
                        help="Scanner les réseaux WiFi")
    parser.add_argument("--bluetooth",   "-b",  action="store_true",
                        help="Scanner les appareils Bluetooth")
    parser.add_argument("--live",        "-l",  action="store_true",
                        help="Capture de paquets en direct")
    parser.add_argument("--count",       "-c",  type=int, default=100,
                        help="Nombre de paquets (live capture)")
    parser.add_argument("--version",     "-v",  action="store_true",
                        help="Version")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        interactive_mode()
        return

    print_banner()

    if args.version:
        console.print(f"[bold]NetRadar[/bold] v{VERSION}")
        return

    if args.full:
        full_scan()

    if args.interfaces:
        display_interfaces(get_interfaces())

    if args.hosts is not None:
        net = args.hosts
        if net == "auto":
            local = get_local_ip()
            net   = ".".join(local.split(".")[:3]) + ".0/24"
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn(f"[cyan]Scan {net}..."),
                      BarColumn(bar_width=35),
                      TaskProgressColumn(),
                      console=console) as prog:
            task = prog.add_task(net, total=256)
            def cb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d, total=t)
            hosts = scan_network(net, cb)
        display_hosts(hosts)

    if args.ports:
        ports = _parse_ports(args.port_range)
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn(f"[cyan]Scan {args.ports}..."),
                      BarColumn(bar_width=35),
                      TaskProgressColumn(),
                      console=console) as prog:
            task = prog.add_task(args.ports, total=len(ports))
            def pcb(d, t, _task=task, _prog=prog): _prog.update(_task, completed=d)
            open_p = scan_ports(args.ports, ports, pcb)
        display_ports(args.ports, open_p)

    if args.wifi:
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn("[cyan]Scan WiFi..."),
                      console=console) as prog:
            prog.add_task("wifi", total=None)
            nets = scan_wifi()
        display_wifi(nets)

    if args.bluetooth:
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn("[cyan]Scan Bluetooth..."),
                      console=console) as prog:
            prog.add_task("bt", total=None)
            devs = scan_bluetooth()
        display_bluetooth(devs)

    if args.live:
        live_capture(count=args.count)


if __name__ == "__main__":
    main()
