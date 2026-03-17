#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar services module — HTTP, SSL, DNS, NetBIOS, SNMP, traceroute, geo, whois, mDNS.
"""

import sys
import re
import ssl
import socket
import time
import json
import threading
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional

from .core import (
    console, box, Table, Panel,
    run_cmd, is_valid_ip, is_private_ip, reverse_dns,
    build_snmp_get, parse_snmp_string,
    SNMP_COMMUNITIES, SNMP_OIDS, MDNS_SERVICES,
)

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
    try:
        import dns.resolver, dns.reversename, dns.zone, dns.query
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
    except ImportError:
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
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
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
    except ImportError:
        pass

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
