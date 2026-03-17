#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar capture module — live packet capture (lazy scapy).
"""

import sys
from datetime import datetime
from typing import Optional

from .core import (
    console, TCP_SERVICES,
)

# ══════════════════════════════════════════════════════════════
#  LIVE PACKET CAPTURE
# ══════════════════════════════════════════════════════════════
def live_capture(iface: Optional[str] = None, count: int = 100):
    try:
        import scapy.all as scapy
        from scapy.layers.l2 import ARP, Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        console.print("[red]Scapy requis: pip install scapy[/red]")
        if sys.platform == "win32":
            console.print("[yellow]Installez aussi Npcap: npcap.com[/yellow]")
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
