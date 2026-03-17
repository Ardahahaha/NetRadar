 ![Uploading Capture d'écran 2026-03-16 122635.png…]()

🚀 Features
#ModuleDescription1
📊 Full Advanced ScanAll modules at once: hosts, ports, HTTP, SSL, SNMP, WiFi, BT, vulns2

🔍 Host DiscoveryActive devices, OS fingerprinting via TTL, MAC + vendor3

🔓 TCP Port ScannerOpen ports, service name, banner grabbing4

📡 UDP Port ScannerDNS, SNMP, NTP, SSDP, mDNS, DHCP and more5

🌐 HTTP/HTTPS ScannerStatus code, server, page title, technologies, security headers6

🔒 SSL/TLS ScannerCertificates, expiry, cipher suite, SANs7

🗂️ DNS ScannerA/AAAA/MX/NS/TXT/CNAME/SOA records + AXFR zone transfer attempt8

🖥️ NetBIOS/SMB ScannerWindows names, workgroups9

📶 SNMP ScannerCommunity strings, sysDescr, sysName10

📡 WiFi ScannerSSID, BSSID, signal (dBm + %), channel, security, AP vendor11🦷 Bluetooth ScannerBLE + classic, RSSI, device type12🗺️ TracerouteHop-by-hop path to a target13

🌍 IP GeolocationCountry, city, ISP, coordinates14

📋 WHOIS LookupRegistrar, org, creation/expiry dates for IP or domain15

📢 mDNS/ZeroconfPrinters, Chromecast, AirPlay, SSH and other local services16

📈 Network StatisticsBytes in/out, active connections, TCP states17

🔑 Default Credentials CheckTest FTP/HTTP/MySQL with common default passwords18

⚠️ Vulnerability AnalysisDetect known CVEs from service banners (30+ signatures)19🖧 Network InterfacesIP, MAC, subnet mask, IPv6, vendor per interface20

🕵️ Live CaptureReal-time packet display: TCP / UDP / ICMP / ARP (Npcap/root required)

📦 Requirements

Python 3.8+
(Windows) Npcap for packet capture with Scapy


⚙️ Installation
Windows
Double-click install.bat or run it in a terminal:
batinstall.bat
It automatically installs all dependencies and guides you through the Npcap setup.
Linux / macOS
bashpip install -r requirements.txt

For packet capture on Linux, run with sudo or grant raw socket permissions to Python.


🎮 Usage
Interactive mode (menu)
bashpython netRadar.py
Launches a numbered interactive menu letting you choose each module.
Direct CLI mode
bash# Full scan (interfaces + hosts + ports + WiFi + Bluetooth)
python netRadar.py --full

# Network interfaces
python netRadar.py --interfaces

# Host discovery (automatic local network)
python netRadar.py --hosts

# Host discovery on a specific network
python netRadar.py --hosts 192.168.1.0/24

# Port scan (common ports by default)
python netRadar.py --ports 192.168.1.1

# Port scan on a custom range
python netRadar.py --ports 192.168.1.1 --port-range 1-1024
python netRadar.py --ports 192.168.1.1 --port-range 80,443,8080

# WiFi scan
python netRadar.py --wifi

# Bluetooth scan
python netRadar.py --bluetooth

# Live packet capture (100 packets by default)
python netRadar.py --live
python netRadar.py --live --count 200

# Version
python netRadar.py --version

📚 Dependencies
LibraryMin. versionRoleRequiredrich13.0.0Colored CLI interface✅ Yesscapy2.5.0Advanced ARP scan + packet capture⭕ Nopython-nmap0.7.1Advanced OS detection (requires nmap installed)⭕ Nonetifaces0.11.0Detailed network interfaces⭕ Nopywifi1.1.12Native WiFi scan (Windows / Linux)⭕ Nobleak0.21.0Bluetooth BLE scan⭕ No

Optional modules enhance features but are not required. NetRadar uses system fallbacks (arp -a, ip addr, netsh, nmcli, PowerShell) when libraries are unavailable.


🔑 Permissions
Some features require elevated privileges:

Windows: run as Administrator for packet capture and ARP scan
Linux / macOS: use sudo for packet capture with Scapy

NetRadar indicates at startup whether admin rights are active.

📁 Project Structure
NetRadar/
├── netRadar.py        # Main script
├── requirements.txt   # Python dependencies
├── install.bat        # Automatic Windows installer
└── README.md

⚠️ Legal Disclaimer
This tool is intended for educational purposes and testing only, on networks you own or have explicit authorization to test. Any unauthorized use on third-party networks is illegal. The author assumes no responsibility for any misuse.
