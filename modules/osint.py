#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRadar OSINT module — open-source intelligence gathering.
"""

import re
import socket
import json
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

from .core import (
    console, box, Table, Panel, Rule,
    is_valid_ip, is_private_ip, reverse_dns,
)

# ══════════════════════════════════════════════════════════════
#  OSINT — RENSEIGNEMENT EN SOURCE OUVERTE
# ══════════════════════════════════════════════════════════════

_OSINT_UA = "NetRadar-OSINT/2.1 (open-source network intelligence)"

def _osint_fetch(url: str, timeout: int = 8) -> Optional[Dict]:
    """Requête JSON vers une API publique. Retourne le dict ou None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _OSINT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None

def _osint_fetch_text(url: str, timeout: int = 8, max_bytes: int = 8192) -> str:
    """Requête texte brut vers une API publique (limité à max_bytes)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _OSINT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(max_bytes).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _osint_post(url: str, payload: Dict, content_type: str = "application/json",
                timeout: int = 8) -> Optional[Dict]:
    """POST JSON ou form-encoded vers une API publique."""
    try:
        if content_type == "application/json":
            body = json.dumps(payload).encode("utf-8")
        else:
            body = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"User-Agent": _OSINT_UA, "Content-Type": content_type})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None

def osint_lookup(target: str, scan_data: Optional[Dict] = None) -> Dict:
    """
    OSINT multi-sources approfondi sur une IP ou un domaine.
    Sources : ip-api.com · ipinfo.io · BGPView · crt.sh · Shodan InternetDB
              AlienVault OTX · ThreatFox · URLhaus · Feodo Tracker (abuse.ch)
              RDAP (WHOIS structuré) · DNS over HTTPS (SPF/DMARC/DKIM)
              HackerTarget · Wayback CDX · URLScan.io · robots.txt · security.txt
    Toutes gratuites, publiques, légales — aucune clé API requise.
    """
    result: Dict = {
        "target":          target,
        "is_ip":           is_valid_ip(target),
        "is_private":      False,
        "resolved_ip":     "",
        "geo":             {},
        "ipinfo":          {},
        "asn":             {},
        "rdap":            {},
        "reverse_dns":     "",
        "reverse_ip":      [],
        "subdomains":      [],
        "certs":           [],
        "shodan":          {},
        "otx":             {},
        "threatfox":       [],
        "urlhaus":         {},
        "feodo":           False,
        "email_security":  {},
        "robots_txt":      "",
        "security_txt":    "",
        "wayback":         {},
        "wayback_history": [],
        "passivedns":      [],
        "urlscan":         [],
        "scan_context":    {},
        "threat_score":    0,
        "threat_flags":    [],
        "errors":          [],
    }

    is_ip         = is_valid_ip(target)
    ip_target     = target if is_ip else ""
    domain_target = target if not is_ip else ""

    if is_ip:
        result["is_private"]  = is_private_ip(target)
        result["resolved_ip"] = target
        rdns = reverse_dns(target)
        result["reverse_dns"] = rdns or ""
        domain_target = rdns or ""
    else:
        try:
            ip_target = socket.gethostbyname(target)
            result["resolved_ip"] = ip_target
            result["is_private"]  = is_private_ip(ip_target)
        except Exception:
            ip_target = ""

    private = result["is_private"]

    # ── 1. Géolocalisation enrichie (ip-api.com) ──────────────
    def fetch_geo():
        if not ip_target or private:
            return
        url = (f"http://ip-api.com/json/{ip_target}?"
               "fields=status,country,countryCode,regionName,city,zip,"
               "isp,org,as,asname,reverse,mobile,proxy,hosting,lat,lon,query,timezone")
        data = _osint_fetch(url)
        if data and data.get("status") == "success":
            result["geo"] = data

    # ── 2. IPInfo.io (ASN, société, abuse contact) ─────────────
    def fetch_ipinfo():
        if not ip_target or private:
            return
        data = _osint_fetch(f"https://ipinfo.io/{ip_target}/json", timeout=8)
        if data and "bogon" not in data:
            result["ipinfo"] = data

    # ── 3. BGP / ASN via BGPView ───────────────────────────────
    def fetch_asn():
        if not ip_target or private:
            return
        data = _osint_fetch(f"https://api.bgpview.io/ip/{ip_target}", timeout=10)
        if data and data.get("status") == "ok":
            prefixes = data.get("data", {}).get("prefixes", [])
            if prefixes:
                p        = prefixes[0]
                asn_info = p.get("asn", {})
                result["asn"] = {
                    "asn":         asn_info.get("asn", ""),
                    "name":        asn_info.get("name", ""),
                    "description": asn_info.get("description", ""),
                    "prefix":      p.get("prefix", ""),
                    "country":     asn_info.get("country_code", ""),
                    "rir":         (p.get("rir_allocation") or {}).get("rir_name", ""),
                }

    # ── 4. RDAP — WHOIS structuré JSON ────────────────────────
    def fetch_rdap():
        try:
            if ip_target and not private:
                # Bootstrap RDAP : essayer ARIN puis RIPE puis APNIC
                for rdap_url in [
                    f"https://rdap.arin.net/registry/ip/{ip_target}",
                    f"https://rdap.db.ripe.net/ip/{ip_target}",
                    f"https://rdap.apnic.net/ip/{ip_target}",
                ]:
                    data = _osint_fetch(rdap_url, timeout=8)
                    if data and "name" in data:
                        net = {
                            "name":       data.get("name", ""),
                            "handle":     data.get("handle", ""),
                            "type":       data.get("type", ""),
                            "country":    data.get("country", ""),
                            "start_addr": data.get("startAddress", ""),
                            "end_addr":   data.get("endAddress", ""),
                            "entities":   [],
                        }
                        for ent in data.get("entities", [])[:4]:
                            roles = ent.get("roles", [])
                            vcard = ent.get("vcardArray", [None, []])[1]
                            name  = next((v[3] for v in vcard if v[0] == "fn"), "")
                            email = next((v[3] for v in vcard if v[0] == "email"), "")
                            net["entities"].append({
                                "roles": roles, "name": name, "email": email})
                        result["rdap"] = net
                        break
            elif domain_target and "." in domain_target:
                parts = domain_target.rstrip(".").split(".")
                root  = ".".join(parts[-2:]) if len(parts) >= 2 else domain_target
                data  = _osint_fetch(f"https://rdap.org/domain/{root}", timeout=9)
                if data:
                    events = {e.get("eventAction", ""): e.get("eventDate", "")[:10]
                              for e in data.get("events", [])}
                    ns = [n.get("ldhName", "") for n in data.get("nameservers", [])]
                    entities = []
                    for ent in data.get("entities", [])[:3]:
                        roles = ent.get("roles", [])
                        vcard = ent.get("vcardArray", [None, []])[1]
                        name  = next((v[3] for v in vcard if v[0] == "fn"),  "")
                        email = next((v[3] for v in vcard if v[0] == "email"),"")
                        entities.append({"roles": roles, "name": name, "email": email})
                    result["rdap"] = {
                        "name":        data.get("ldhName", root),
                        "handle":      data.get("handle", ""),
                        "status":      data.get("status", []),
                        "registered":  events.get("registration", ""),
                        "updated":     events.get("last changed", ""),
                        "expires":     events.get("expiration", ""),
                        "nameservers": ns,
                        "entities":    entities,
                    }
        except Exception as e:
            result["errors"].append(f"RDAP: {e}"[:60])

    # ── 5. Shodan InternetDB (gratuit, sans clé) ───────────────
    def fetch_shodan():
        if not ip_target or private:
            return
        data = _osint_fetch(f"https://internetdb.shodan.io/{ip_target}", timeout=8)
        if data and "ip" in data:
            result["shodan"] = {
                "ports":     data.get("ports",     []),
                "hostnames": data.get("hostnames", []),
                "cpes":      data.get("cpes",      []),
                "tags":      data.get("tags",      []),
                "vulns":     data.get("vulns",     []),
            }

    # ── 6. AlienVault OTX — Threat Intelligence ───────────────
    def fetch_otx():
        if private:
            return
        q = ip_target if is_ip else domain_target
        if not q:
            return
        itype  = "IPv4" if is_ip else "domain"
        data   = _osint_fetch(
            f"https://otx.alienvault.com/api/v1/indicators/{itype}/{q}/general",
            timeout=10)
        if data:
            pulse_info    = data.get("pulse_info",    {})
            malware_list  = data.get("malware",       [])
            result["otx"] = {
                "pulse_count":     pulse_info.get("count", 0),
                "pulse_references": [p.get("name", "") for p in
                                     pulse_info.get("pulses", [])[:5]],
                "malware_families": list({m.get("family","") for m in malware_list
                                          if m.get("family")})[:6],
                "type_title":      data.get("type_title", ""),
                "whois":           data.get("whois", ""),
                "reputation":      data.get("reputation", 0),
            }

    # ── 7. ThreatFox (abuse.ch) — IOC database ────────────────
    def fetch_threatfox():
        if private:
            return
        q = ip_target or domain_target
        if not q:
            return
        data = _osint_post(
            "https://threatfox-api.abuse.ch/api/v1/",
            {"query": "search_ioc", "search_term": q},
            timeout=9)
        if data and data.get("query_status") == "ok":
            iocs: List[Dict] = []
            for entry in (data.get("data") or [])[:6]:
                iocs.append({
                    "ioc":          entry.get("ioc",          ""),
                    "ioc_type":     entry.get("ioc_type",     ""),
                    "threat_type":  entry.get("threat_type",  ""),
                    "malware":      entry.get("malware",      ""),
                    "confidence":   entry.get("confidence_level", 0),
                    "first_seen":   entry.get("first_seen", "")[:10],
                })
            result["threatfox"] = iocs

    # ── 8. URLhaus (abuse.ch) — malware URL database ──────────
    def fetch_urlhaus():
        if private:
            return
        q = ip_target or domain_target
        if not q:
            return
        data = _osint_post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            {"host": q},
            content_type="application/x-www-form-urlencoded",
            timeout=9)
        if data:
            result["urlhaus"] = {
                "query_status": data.get("query_status", ""),
                "urls_count":   len(data.get("urls", [])),
                "blacklists":   data.get("blacklists", {}),
                "urls":         [{
                    "url":         u.get("url", "")[:80],
                    "url_status":  u.get("url_status", ""),
                    "threat":      u.get("threat", ""),
                    "date_added":  u.get("date_added", "")[:10],
                } for u in (data.get("urls") or [])[:5]],
            }

    # ── 9. Feodo Tracker — C2 botnet IPs (abuse.ch) ───────────
    def fetch_feodo():
        if not ip_target or private:
            return
        blocklist = _osint_fetch(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            timeout=10)
        if blocklist and isinstance(blocklist, list):
            for entry in blocklist:
                if entry.get("ip_address") == ip_target:
                    result["feodo"] = True
                    result["feodo_detail"] = {
                        "malware":      entry.get("malware", ""),
                        "port":         entry.get("port", ""),
                        "last_online":  entry.get("last_online", ""),
                        "first_seen":   entry.get("first_seen", ""),
                    }
                    break

    # ── 10. Certificate Transparency — crt.sh ─────────────────
    def fetch_certs():
        dom = domain_target
        if not dom or "." not in dom:
            return
        parts = dom.rstrip(".").split(".")
        root  = ".".join(parts[-2:]) if len(parts) >= 2 else dom
        enc   = urllib.parse.quote(f"%.{root}")
        data  = _osint_fetch(f"https://crt.sh/?q={enc}&output=json", timeout=14)
        if not data or not isinstance(data, list):
            return
        seen: set = set()
        certs_list: List[Dict] = []
        for entry in data[:200]:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and name not in seen and root in name:
                    seen.add(name)
                    certs_list.append({
                        "name":       name,
                        "issuer":     entry.get("issuer_name", "")[:70],
                        "not_before": entry.get("not_before", "")[:10],
                        "not_after":  entry.get("not_after",  "")[:10],
                    })
        result["certs"]     = certs_list[:50]
        result["subdomains"] = sorted({c["name"] for c in certs_list
                                       if c["name"] != root})[:40]

    # ── 11. Sécurité Email — SPF / DMARC / DKIM ───────────────
    def fetch_email_security():
        dom = domain_target
        if not dom or "." not in dom or is_ip:
            return
        parts = dom.rstrip(".").split(".")
        root  = ".".join(parts[-2:]) if len(parts) >= 2 else dom

        def doh_txt(name: str) -> List[str]:
            enc  = urllib.parse.quote(name)
            data = _osint_fetch(
                f"https://dns.google/resolve?name={enc}&type=TXT", timeout=7)
            if not data:
                return []
            records = []
            for ans in data.get("Answer", []):
                val = ans.get("data", "").strip('"')
                records.append(val)
            return records

        spf_records   = [r for r in doh_txt(root) if r.startswith("v=spf")]
        dmarc_records = [r for r in doh_txt(f"_dmarc.{root}") if "v=DMARC" in r]

        dkim_found: List[str] = []
        for selector in ("default", "google", "mail", "dkim", "k1", "selector1", "selector2"):
            recs = doh_txt(f"{selector}._domainkey.{root}")
            if any("v=DKIM" in r or "p=" in r for r in recs):
                dkim_found.append(selector)

        result["email_security"] = {
            "spf":    spf_records[0][:120]  if spf_records   else "",
            "dmarc":  dmarc_records[0][:120] if dmarc_records else "",
            "dkim_selectors": dkim_found,
        }

    # ── 12. Reverse IP — domaines sur la même adresse ─────────
    def fetch_reverse_ip():
        if not ip_target or private:
            return
        txt = _osint_fetch_text(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip_target}", timeout=9)
        if txt and "error" not in txt.lower() and "API count" not in txt:
            result["reverse_ip"] = [d.strip() for d in txt.splitlines()
                                    if d.strip() and "." in d][:30]

    # ── 13. DNS Lookup étendu (HackerTarget) ──────────────────
    def fetch_passivedns():
        q = domain_target or ip_target
        if not q:
            return
        txt = _osint_fetch_text(
            f"https://api.hackertarget.com/dnslookup/?q={q}", timeout=9)
        if txt and "error" not in txt.lower() and "API count" not in txt:
            result["passivedns"] = [l.strip() for l in txt.splitlines() if l.strip()][:30]

    # ── 14. Wayback Machine — snapshot + historique CDX ───────
    def fetch_wayback():
        q = domain_target or ip_target
        if not q:
            return
        snap_data = _osint_fetch(f"http://archive.org/wayback/available?url={q}", timeout=7)
        if snap_data:
            result["wayback"] = snap_data.get("archived_snapshots", {}).get("closest", {})
        # CDX — dernières URLs archivées
        enc  = urllib.parse.quote(q)
        cdx  = _osint_fetch(
            f"http://web.archive.org/cdx/search/cdx?url={enc}/*"
            f"&output=json&limit=10&fl=timestamp,original,statuscode&collapse=digest",
            timeout=10)
        if cdx and isinstance(cdx, list) and len(cdx) > 1:
            history = []
            for row in cdx[1:]:          # row 0 = header
                if len(row) >= 3:
                    ts = row[0]
                    history.append({
                        "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                        "url":  row[1][:90],
                        "code": row[2],
                    })
            result["wayback_history"] = history

    # ── 15. URLScan.io — scans publics ────────────────────────
    def fetch_urlscan():
        q = domain_target or ip_target
        if not q or private:
            return
        search_q = urllib.parse.quote(
            f"domain:{q}" if not is_ip else f"ip:{q}")
        data = _osint_fetch(
            f"https://urlscan.io/api/v1/search/?q={search_q}&size=6", timeout=9)
        if data and "results" in data:
            scans: List[Dict] = []
            for r in data["results"][:6]:
                page = r.get("page", {})
                task = r.get("task", {})
                scans.append({
                    "url":     page.get("url",     "")[:80],
                    "ip":      page.get("ip",      ""),
                    "country": page.get("country", ""),
                    "server":  page.get("server",  "")[:25],
                    "date":    task.get("time",    "")[:10],
                    "score":   r.get("verdicts", {}).get("overall", {}).get("score", 0),
                    "malicious": r.get("verdicts", {}).get("overall", {}).get("malicious", False),
                })
            result["urlscan"] = scans

    # ── 16. robots.txt + security.txt ─────────────────────────
    def fetch_public_files():
        dom = domain_target
        if not dom or is_ip or private:
            return
        for scheme in ("https", "http"):
            txt = _osint_fetch_text(f"{scheme}://{dom}/robots.txt",
                                    timeout=6, max_bytes=3000)
            if txt and "User-agent" in txt:
                result["robots_txt"] = txt[:1500]
                break
        for scheme in ("https", "http"):
            stxt = _osint_fetch_text(f"{scheme}://{dom}/.well-known/security.txt",
                                     timeout=6, max_bytes=2000)
            if stxt and ("Contact:" in stxt or "contact:" in stxt):
                result["security_txt"] = stxt[:1000]
                break

    # ── 17. Enrichissement avec données de scan existantes ────
    def enrich_from_scan():
        if not scan_data:
            return
        ctx: Dict = {}
        if "ports" in scan_data:
            open_p             = [p for p in scan_data["ports"] if p.get("state") == "open"]
            ctx["open_ports"]  = [p["port"] for p in open_p]
            ctx["services"]    = [f"{p['port']}/{p.get('service','?')}" for p in open_p]
        if "http" in scan_data:
            h                  = scan_data["http"]
            ctx["http_server"] = h.get("server", "")
            ctx["http_title"]  = h.get("title",  "")
            ctx["http_tech"]   = h.get("tech",   [])
        if "ssl" in scan_data:
            s                  = scan_data["ssl"]
            ctx["ssl_cn"]      = s.get("cn",     "")
            ctx["ssl_issuer"]  = s.get("issuer", "")
            ctx["ssl_sans"]    = s.get("sans",   [])
        if "dns" in scan_data:
            ctx["dns_records"] = scan_data["dns"]
        result["scan_context"] = ctx

    # ── Lancement parallèle des fetchers ──────────────────────
    fetch_tasks = [
        fetch_geo, fetch_ipinfo, fetch_asn, fetch_rdap,
        fetch_shodan, fetch_otx, fetch_threatfox, fetch_urlhaus, fetch_feodo,
        fetch_certs, fetch_email_security, fetch_reverse_ip,
        fetch_passivedns, fetch_wayback, fetch_urlscan,
        fetch_public_files, enrich_from_scan,
    ]
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(t) for t in fetch_tasks]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                result["errors"].append(str(e)[:70])

    # ── Calcul du score de menace ──────────────────────────────
    score = 0
    flags: List[str] = []

    geo = result["geo"]
    if geo.get("proxy"):
        score += 20;  flags.append("Proxy / VPN / Tor détecté")
    if geo.get("hosting"):
        score += 8;   flags.append("Hébergement datacenter")

    shodan = result["shodan"]
    bad_tags = {"malware", "botnet", "c2", "scanner", "spam",
                "phishing", "tor", "vpn", "self-signed"}
    for tag in shodan.get("tags", []):
        if tag.lower() in bad_tags:
            score += 25; flags.append(f"Tag Shodan suspect : {tag}")
    vuln_count = len(shodan.get("vulns", []))
    if vuln_count:
        score += min(vuln_count * 12, 40)
        flags.append(f"{vuln_count} CVE(s) exposé(s) selon Shodan")

    otx = result["otx"]
    pulse_count = otx.get("pulse_count", 0)
    if pulse_count:
        score += min(pulse_count * 4, 40)
        flags.append(f"Présent dans {pulse_count} pulse(s) AlienVault OTX")
    if otx.get("malware_families"):
        score += 20
        flags.append("Familles de malware OTX : " +
                      ", ".join(otx["malware_families"][:3]))

    if result["threatfox"]:
        score += 50; flags.append("IOC référencé sur ThreatFox (abuse.ch)")

    urlhaus = result["urlhaus"]
    if urlhaus.get("query_status") == "is_host":
        score += 40; flags.append("Hôte dans URLhaus — distribution de malware (abuse.ch)")

    if result.get("feodo"):
        score += 65; flags.append("IP C2 botnet — Feodo Tracker (Emotet/Dridex/TrickBot)")

    for s in result["urlscan"]:
        if s.get("malicious"):
            score += 15; flags.append("Scan URLScan.io marqué malveillant"); break

    email = result["email_security"]
    if not is_ip and domain_target and "." in domain_target:
        if not email.get("spf") and not email.get("dmarc"):
            score += 8; flags.append("Aucune protection email (SPF + DMARC absents)")
        elif not email.get("dmarc"):
            score += 4; flags.append("DMARC absent (risque spoofing email)")

    result["threat_score"] = min(score, 100)
    result["threat_flags"]  = flags
    return result


def display_osint(data: Dict):
    target = data.get("target", "?")
    console.print(Rule(f"[bold cyan]  OSINT APPROFONDI — {target}  [/bold cyan]",
                       style="cyan"))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 0.  SCORE DE MENACE (banner visible en premier)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    score = data.get("threat_score", 0)
    flags = data.get("threat_flags", [])
    if score >= 60:
        sc_color, sc_label = "red",    "DANGEREUX"
    elif score >= 30:
        sc_color, sc_label = "yellow", "SUSPECT"
    elif score > 0:
        sc_color, sc_label = "cyan",   "FAIBLE RISQUE"
    else:
        sc_color, sc_label = "green",  "PROPRE"

    bar_fill = int(score / 5)
    bar_str  = f"[{sc_color}]{'█' * bar_fill}{'░' * (20 - bar_fill)}[/{sc_color}]"
    flag_str = ("\n".join(f"  [{sc_color}]▸[/{sc_color}] {f}" for f in flags)
                if flags else f"  [{sc_color}]Aucun signal négatif détecté[/{sc_color}]")
    resolved = data.get("resolved_ip", "")
    ip_line  = f"  IP résolue : [cyan]{resolved}[/cyan]\n" if resolved else ""
    console.print(Panel(
        f"{ip_line}  Score de menace : {bar_str} "
        f"[bold {sc_color}]{score}/100 — {sc_label}[/bold {sc_color}]\n\n"
        f"{flag_str}",
        title=f"[bold {sc_color}]  Évaluation de la menace[/bold {sc_color}]",
        border_style=sc_color))
    console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 1.  IDENTITÉ IP / RÉSEAU / GÉO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    geo    = data.get("geo",    {})
    ipinfo = data.get("ipinfo", {})
    asn_d  = data.get("asn",   {})
    rdns   = data.get("reverse_dns", "")
    if geo or ipinfo or asn_d or rdns:
        t = Table(title="[bold cyan]Identité IP / Réseau / Géolocalisation[/bold cyan]",
                  box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
        t.add_column("Champ",  style="cyan",  min_width=22)
        t.add_column("Valeur", style="white", min_width=42)
        if rdns:
            t.add_row("Reverse DNS", rdns)
        if geo.get("country"):
            cc = geo.get("countryCode", "").lower()
            t.add_row("Pays", f"{geo.get('country','')}  [{cc.upper()}]")
        if geo.get("regionName") or geo.get("city"):
            t.add_row("Région / Ville",
                      f"{geo.get('regionName','')} — {geo.get('city','')}")
        if geo.get("timezone"):
            t.add_row("Fuseau horaire", geo.get("timezone", ""))
        if geo.get("isp"):
            t.add_row("ISP", geo.get("isp", ""))
        if geo.get("org"):
            t.add_row("Organisation", geo.get("org", ""))
        if geo.get("as"):
            t.add_row("AS (ip-api)", geo.get("as", ""))
        pv = geo.get("proxy")
        if pv is not None:
            t.add_row("Proxy / VPN / Tor",
                      "[bold red]OUI[/bold red]" if pv else "[green]NON[/green]")
        hv = geo.get("hosting")
        if hv is not None:
            t.add_row("Datacenter",
                      "[yellow]OUI[/yellow]" if hv else "[green]NON[/green]")
        if geo.get("lat"):
            t.add_row("Coordonnées GPS", f"{geo.get('lat')} , {geo.get('lon')}")
        if ipinfo.get("hostname") and not rdns:
            t.add_row("Hostname", ipinfo.get("hostname", ""))
        if ipinfo.get("org") and not geo.get("org"):
            t.add_row("Organisation", ipinfo.get("org", ""))
        if asn_d.get("asn"):
            t.add_row("ASN",          f"AS{asn_d['asn']}")
        if asn_d.get("name"):
            t.add_row("Nom ASN",      asn_d.get("name", ""))
        if asn_d.get("description") and asn_d.get("description") != asn_d.get("name"):
            t.add_row("Description",  asn_d.get("description", "")[:60])
        if asn_d.get("prefix"):
            t.add_row("Préfixe CIDR", asn_d.get("prefix", ""))
        if asn_d.get("rir"):
            t.add_row("RIR",          asn_d.get("rir", ""))
        console.print(t); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 2.  RDAP — WHOIS STRUCTURÉ
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    rdap = data.get("rdap", {})
    if rdap:
        tr = Table(title="[bold cyan]RDAP — WHOIS Structuré[/bold cyan]",
                   box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
        tr.add_column("Champ",  style="cyan",  min_width=20)
        tr.add_column("Valeur", style="white", min_width=44)
        for k, lbl in [("name","Nom réseau"),("handle","Handle"),("type","Type"),
                       ("country","Pays"),("start_addr","IP début"),
                       ("end_addr","IP fin"),("prefix","Préfixe")]:
            if rdap.get(k):
                tr.add_row(lbl, str(rdap[k]))
        for k, lbl in [("registered","Enregistré"),("updated","Mis à jour"),
                       ("expires","Expiration")]:
            if rdap.get(k):
                tr.add_row(lbl, rdap[k])
        if rdap.get("status"):
            tr.add_row("Statut", ", ".join(rdap["status"][:4]))
        if rdap.get("nameservers"):
            tr.add_row("Serveurs de noms", "\n".join(rdap["nameservers"][:6]))
        for ent in rdap.get("entities", []):
            roles = "/".join(ent.get("roles", []))
            name  = ent.get("name",  "")
            email = ent.get("email", "")
            parts_e = []
            if name:  parts_e.append(name)
            if email: parts_e.append(f"[blue]{email}[/blue]")
            if parts_e:
                tr.add_row(f"Contact ({roles})", "  ".join(parts_e))
        console.print(tr); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 3.  SHODAN INTERNETDB
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    shodan = data.get("shodan", {})
    if shodan:
        ts = Table(title="[bold cyan]Shodan InternetDB — Empreinte internet passive[/bold cyan]",
                   box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
        ts.add_column("Champ",  style="cyan",  min_width=20)
        ts.add_column("Valeur", style="white", min_width=55)
        if shodan.get("ports"):
            ts.add_row("Ports ouverts",
                       "[cyan]" + "  ".join(str(p) for p in shodan["ports"]) + "[/cyan]")
        if shodan.get("hostnames"):
            ts.add_row("Hostnames", "\n".join(shodan["hostnames"][:6]))
        if shodan.get("cpes"):
            ts.add_row("CPE (logiciels détectés)",
                       "\n".join(shodan["cpes"][:6]))
        if shodan.get("tags"):
            tags_colored = []
            bad = {"malware","botnet","c2","scanner","spam","phishing","tor","vpn"}
            for tag in shodan["tags"]:
                c = "red" if tag.lower() in bad else "yellow"
                tags_colored.append(f"[{c}]{tag}[/{c}]")
            ts.add_row("Tags", "  ".join(tags_colored))
        if shodan.get("vulns"):
            vuln_str = "\n".join(
                f"[bold red]{v}[/bold red]" for v in shodan["vulns"][:10])
            ts.add_row("CVE exposées", vuln_str)
        console.print(ts); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 4.  THREAT INTELLIGENCE (OTX + ThreatFox + URLhaus + Feodo)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    otx      = data.get("otx", {})
    tfox     = data.get("threatfox", [])
    urlhaus  = data.get("urlhaus",  {})
    feodo    = data.get("feodo",    False)

    if otx or tfox or urlhaus or feodo:
        tt = Table(title="[bold red]Threat Intelligence — Sources abuse.ch / AlienVault OTX[/bold red]",
                   box=box.DOUBLE_EDGE, header_style="bold red", show_lines=True)
        tt.add_column("Source",       style="bold red", min_width=18)
        tt.add_column("Résultat",     style="white",    min_width=55)

        # OTX
        pc = otx.get("pulse_count", 0)
        if pc:
            refs  = otx.get("pulse_references", [])
            fams  = otx.get("malware_families", [])
            lines = [f"[red]{pc} pulse(s)[/red]"]
            if refs:
                lines += [f"  • {r[:70]}" for r in refs]
            if fams:
                lines.append("Familles : " + ", ".join(fams))
            tt.add_row("AlienVault OTX", "\n".join(lines))
        elif otx:
            tt.add_row("AlienVault OTX", "[green]Aucun pulse connu[/green]")

        # ThreatFox
        if tfox:
            rows = []
            for ioc in tfox:
                rows.append(
                    f"[red]{ioc['ioc']}[/red]  [{ioc['ioc_type']}]  "
                    f"{ioc['threat_type']} — {ioc['malware']}  "
                    f"(confiance {ioc['confidence']}%  vu le {ioc['first_seen']})")
            tt.add_row("ThreatFox", "\n".join(rows))
        else:
            tt.add_row("ThreatFox", "[green]Aucun IOC connu[/green]")

        # URLhaus
        uh_status = urlhaus.get("query_status", "")
        if uh_status == "is_host":
            uh_lines = [f"[red]Hôte référencé — {urlhaus.get('urls_count',0)} URL(s)[/red]"]
            for u in urlhaus.get("urls", []):
                uh_lines.append(
                    f"  [{u['url_status']}] {u['url'][:65]}  ({u['threat']}  {u['date_added']})")
            tt.add_row("URLhaus", "\n".join(uh_lines))
        elif uh_status:
            tt.add_row("URLhaus", "[green]Non référencé[/green]")

        # Feodo
        if feodo:
            fd = data.get("feodo_detail", {})
            tt.add_row("Feodo Tracker",
                       f"[bold red]IP C2 ACTIVE — {fd.get('malware','')}  "
                       f"port {fd.get('port','')}  "
                       f"(vu le {fd.get('last_online','')})[/bold red]")
        else:
            tt.add_row("Feodo Tracker", "[green]Non référencée[/green]")

        console.print(tt); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 5.  SOUS-DOMAINES — CERTIFICATE TRANSPARENCY
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    subs  = data.get("subdomains", [])
    certs = data.get("certs",      [])
    if subs:
        cert_map = {c["name"]: c for c in certs}
        tc = Table(
            title=f"[bold cyan]Sous-domaines — Certificate Transparency crt.sh  [{len(subs)}][/bold cyan]",
            box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=False)
        tc.add_column("#",             style="dim",    width=4)
        tc.add_column("Sous-domaine",  style="green",  min_width=40)
        tc.add_column("Émetteur CA",   style="dim",    min_width=26)
        tc.add_column("Expire",        style="yellow", width=12)
        for i, sub in enumerate(subs, 1):
            ci     = cert_map.get(sub, {})
            issuer = ci.get("issuer", "")
            m      = re.search(r"O=([^,]+)", issuer)
            tc.add_row(str(i), sub,
                       m.group(1)[:26] if m else issuer[:26],
                       ci.get("not_after", ""))
        console.print(tc); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 6.  SÉCURITÉ EMAIL — SPF / DMARC / DKIM
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    email = data.get("email_security", {})
    if email:
        te = Table(title="[bold cyan]Sécurité Email — SPF / DMARC / DKIM[/bold cyan]",
                   box=box.DOUBLE_EDGE, header_style="bold magenta", show_lines=True)
        te.add_column("Protocole", style="cyan",  min_width=12)
        te.add_column("Statut",    style="bold",  width=12)
        te.add_column("Valeur",    style="dim",   min_width=55)

        spf = email.get("spf", "")
        te.add_row("SPF",
                   "[green]OK[/green]"  if spf else "[red]ABSENT[/red]",
                   spf[:90] if spf else "[red]Pas de politique SPF — risque spoofing[/red]")

        dmarc = email.get("dmarc", "")
        te.add_row("DMARC",
                   "[green]OK[/green]"  if dmarc else "[red]ABSENT[/red]",
                   dmarc[:90] if dmarc else "[red]Pas de DMARC — pas de protection anti-spoofing[/red]")

        dkim_sels = email.get("dkim_selectors", [])
        te.add_row("DKIM",
                   "[green]OK[/green]" if dkim_sels else "[yellow]?[/yellow]",
                   "Sélecteurs actifs : " + ", ".join(dkim_sels)
                   if dkim_sels else "[dim]Aucun sélecteur courant trouvé[/dim]")
        console.print(te); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 7.  REVERSE IP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    rev_ip = data.get("reverse_ip", [])
    if rev_ip:
        tri = Table(
            title=f"[bold cyan]Reverse IP — Domaines co-hébergés [{len(rev_ip)}][/bold cyan]",
            box=box.SIMPLE_HEAD, header_style="bold magenta")
        tri.add_column("#",       style="dim",   width=4)
        tri.add_column("Domaine", style="green", min_width=50)
        for i, dom in enumerate(rev_ip, 1):
            tri.add_row(str(i), dom)
        console.print(tri); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 8.  DNS LOOKUP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pdns = data.get("passivedns", [])
    if pdns:
        td = Table(title="[bold cyan]DNS Lookup étendu (HackerTarget)[/bold cyan]",
                   box=box.SIMPLE_HEAD, header_style="bold magenta")
        td.add_column("Enregistrement", style="cyan", min_width=60)
        for rec in pdns:
            td.add_row(rec)
        console.print(td); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 9.  WAYBACK MACHINE — snapshot + historique CDX
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    wb      = data.get("wayback",         {})
    wb_hist = data.get("wayback_history", [])
    if wb.get("available") or wb_hist:
        wb_lines = []
        if wb.get("available"):
            ts  = wb.get("timestamp", "")
            fmt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            wb_lines.append(
                f"[green]Dernier snapshot :[/green] [cyan]{fmt}[/cyan]  "
                f"[blue]{wb.get('url','')[:70]}[/blue]")
        if wb_hist:
            tw = Table(box=box.SIMPLE, show_header=True,
                       header_style="bold magenta", show_lines=False)
            tw.add_column("Date",   style="dim",   width=12)
            tw.add_column("URL",    style="green", min_width=55)
            tw.add_column("Code",   style="cyan",  width=6)
            for row in wb_hist:
                tw.add_row(row["date"], row["url"][:65], row["code"])
            console.print(Panel(
                "\n".join(wb_lines),
                title="[bold cyan]Wayback Machine (archive.org)[/bold cyan]",
                border_style="cyan"))
            console.print(tw)
        else:
            console.print(Panel(
                "\n".join(wb_lines),
                title="[bold cyan]Wayback Machine (archive.org)[/bold cyan]",
                border_style="cyan"))
        console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 10. URLSCAN.IO
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    urlscans = data.get("urlscan", [])
    if urlscans:
        tu = Table(title="[bold cyan]Historique URLScan.io — Scans publics[/bold cyan]",
                   box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=False)
        tu.add_column("Date",      style="dim",    width=12)
        tu.add_column("URL",       style="green",  min_width=42)
        tu.add_column("IP",        style="cyan",   width=16)
        tu.add_column("Pays",      style="yellow", width=6)
        tu.add_column("Serveur",   style="dim",    width=18)
        tu.add_column("Malveill.", style="red",    width=10)
        for s in urlscans:
            mal = "[bold red]OUI[/bold red]" if s.get("malicious") else "[green]NON[/green]"
            tu.add_row(s.get("date",""), s.get("url","")[:52],
                       s.get("ip",""), s.get("country",""),
                       s.get("server","")[:18], mal)
        console.print(tu); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 11. FICHIERS PUBLICS — robots.txt + security.txt
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    robots  = data.get("robots_txt",   "")
    sec_txt = data.get("security_txt", "")
    if robots:
        console.print(Panel(
            robots[:800],
            title="[bold cyan]robots.txt[/bold cyan]",
            border_style="dim"))
        console.print()
    if sec_txt:
        console.print(Panel(
            sec_txt[:600],
            title="[bold cyan]security.txt (.well-known)[/bold cyan]",
            border_style="green"))
        console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 12. CONTEXTE SCAN
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ctx = data.get("scan_context", {})
    if ctx:
        tctx = Table(title="[bold cyan]Contexte — Données de scan enrichies[/bold cyan]",
                     box=box.SIMPLE_HEAD, header_style="bold magenta", show_lines=True)
        tctx.add_column("Champ",  style="cyan",  min_width=20)
        tctx.add_column("Valeur", style="white", min_width=48)
        if ctx.get("open_ports"):
            tctx.add_row("Ports ouverts",
                         ", ".join(str(p) for p in ctx["open_ports"][:20]))
        if ctx.get("services"):
            tctx.add_row("Services",
                         ", ".join(ctx["services"][:15]))
        if ctx.get("http_server"):
            tctx.add_row("Serveur HTTP",  ctx["http_server"])
        if ctx.get("http_title"):
            tctx.add_row("Titre HTTP",    ctx["http_title"][:70])
        if ctx.get("http_tech"):
            tctx.add_row("Technologies",  ", ".join(ctx["http_tech"][:10]))
        if ctx.get("ssl_cn"):
            tctx.add_row("SSL CN",        ctx["ssl_cn"])
        if ctx.get("ssl_sans"):
            tctx.add_row("SSL SANs",      ", ".join(ctx["ssl_sans"][:10]))
        console.print(tctx); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 13. ERREURS / AVERTISSEMENTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    errors = data.get("errors", [])
    if errors:
        console.print(Panel(
            "\n".join(f"[yellow]• {e}[/yellow]" for e in errors),
            title="[yellow]Avertissements sources[/yellow]",
            border_style="yellow"))
    if data.get("is_private"):
        console.print(Panel(
            "[yellow]IP privée — OSINT internet non applicable.\n"
            "Utilisez les modules Ports, DNS, HTTP, SNMP pour l'analyse locale.[/yellow]",
            title="[yellow]IP Privée[/yellow]", border_style="yellow"))
