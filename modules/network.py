#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar network module — interfaces, host discovery, TCP/UDP port scanning.
"""

import sys
import re
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Tuple

from .core import (
    console, box, Table, Progress, SpinnerColumn, BarColumn, TextColumn,
    run_cmd, get_oui_vendor, ttl_to_os, reverse_dns,
    COMMON_TCP_PORTS, COMMON_UDP_PORTS, TCP_SERVICES,
    build_snmp_get, SNMP_OIDS,
)

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
