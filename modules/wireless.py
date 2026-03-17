#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar wireless module — WiFi and Bluetooth scanning.
"""

import sys
import re
import json
import time
from typing import List, Dict

from .core import (
    console, box, Table,
    run_cmd, get_oui_vendor, _signal_bar,
)

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
    try:
        import pywifi
        from pywifi import const as wifi_const
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
    except ImportError:
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
    try:
        from bleak import BleakScanner
        import asyncio
        try:
            async def _ble_scan_inner(timeout: float = 8.0) -> List[Dict]:
                result = []
                try:
                    for d in await BleakScanner.discover(timeout=timeout):
                        result.append({"name": d.name or "[?]", "address": d.address.upper(),
                                       "rssi": d.rssi, "type": "BLE", "status": "Découvert"})
                except Exception:
                    pass
                return result

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            devs.extend(loop.run_until_complete(_ble_scan_inner()))
            loop.close()
        except Exception:
            pass
    except ImportError:
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
