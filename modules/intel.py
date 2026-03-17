#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar intel module — vulnerability analysis, network stats, default creds, full scan.
"""

import sys
import re
import ipaddress
import urllib.request
import urllib.error
from typing import List, Dict, Optional

from .core import (
    console, box, Table, Panel, Rule, Progress, SpinnerColumn, BarColumn, TextColumn,
    VULN_DB, DEFAULT_CREDS, COMMON_TCP_PORTS, HTTP_PORTS,
    severity_color, run_cmd, get_local_ip,
)
from .network import (get_interfaces, scan_network, display_interfaces,
                      display_hosts, scan_ports, display_ports)
from .services import (scan_http, display_http, scan_ssl, display_ssl,
                       scan_snmp, display_snmp)
from .wireless import scan_wifi, display_wifi, scan_bluetooth, display_bluetooth

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
