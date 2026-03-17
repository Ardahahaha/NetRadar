#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar UI module — interactive menu.
"""

from typing import List

from .core import (
    console, box, Table, Panel, Progress, SpinnerColumn, BarColumn, TextColumn,
    COMMON_TCP_PORTS, DEFAULT_CREDS,
    print_banner, get_local_ip,
)
from .network import (
    get_interfaces, display_interfaces, scan_network, display_hosts,
    scan_ports, display_ports, scan_udp, display_udp,
)
from .services import (
    scan_http, display_http, scan_ssl, display_ssl,
    scan_dns, display_dns, scan_netbios, display_netbios,
    scan_snmp, display_snmp, run_traceroute, display_traceroute,
    geolocate, display_geolocate, whois_lookup, display_whois,
    scan_mdns, display_mdns,
)
from .wireless import scan_wifi, display_wifi, scan_bluetooth, display_bluetooth
from .capture import live_capture
from .intel import (
    check_vulns, display_vulns, get_net_stats, display_netstats,
    check_default_creds, display_default_creds, full_scan,
)
from .osint import osint_lookup, display_osint

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
        ("21", "OSINT — Renseignement",      "Géo, ASN, sous-domaines, reverse IP, certs, Wayback, URLScan","bold magenta"),
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

        elif choice == "21":
            target = _ask("Cible (IP ou domaine)")
            if target:
                console.print("[dim]Interrogation des sources OSINT publiques...[/dim]")
                with Progress(SpinnerColumn(style="magenta"),
                              TextColumn(f"[magenta]OSINT {target}"),
                              console=console) as p:
                    p.add_task("", total=None)
                    osint_data = osint_lookup(target)
                display_osint(osint_data)

        else:
            console.print("[red]Option invalide.[/red]")

        console.print()
        try:
            input("[dim]Appuyez sur Entrée pour continuer...[/dim]")
        except (EOFError, KeyboardInterrupt):
            pass
        console.clear()
        print_banner()
