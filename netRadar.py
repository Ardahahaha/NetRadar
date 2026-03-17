#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, io
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.environ.setdefault("PYTHONUTF8", "1")

import argparse
from modules.core import console, VERSION, COMMON_TCP_PORTS, DEFAULT_CREDS, print_banner, tcp_connect, get_local_ip
from modules.ui import interactive_mode, _ask, _parse_ports
from modules.network import (get_interfaces, display_interfaces, scan_network,
                              display_hosts, scan_ports, display_ports,
                              scan_udp, display_udp)
from modules.services import (scan_http, display_http, scan_ssl, display_ssl,
                               scan_dns, display_dns, scan_netbios, display_netbios,
                               scan_snmp, display_snmp, run_traceroute, display_traceroute,
                               geolocate, display_geolocate, whois_lookup, display_whois,
                               scan_mdns, display_mdns)
from modules.wireless import scan_wifi, display_wifi, scan_bluetooth, display_bluetooth
from modules.capture import live_capture
from modules.intel import (check_vulns, display_vulns, get_net_stats,
                            display_netstats, check_default_creds, display_default_creds,
                            full_scan)
from modules.osint import osint_lookup, display_osint
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn


def main():
    ap = argparse.ArgumentParser(
        description=f"NetRadar v{VERSION} — Advanced Network Intelligence Scanner",
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
  python netRadar.py --osint google.com    OSINT (géo, ASN, certs, reverse IP...)
  python netRadar.py --osint 8.8.8.8       OSINT sur une adresse IP
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
    ap.add_argument("--osint",      "-o",  metavar="TARGET")
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
    if args.osint:
        console.print("[dim]Interrogation des sources OSINT publiques...[/dim]")
        with Progress(SpinnerColumn(style="magenta"),
                      TextColumn(f"[magenta]OSINT {args.osint}"),
                      console=console) as p:
            p.add_task("", total=None)
            osint_data = osint_lookup(args.osint)
        display_osint(osint_data)


if __name__ == "__main__":
    main()
