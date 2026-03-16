 🚀 Features
ModuleDescription🖥️ Network InterfacesDisplay IP, MAC, subnet mask, broadcast and vendor for each interface🔍 Host DiscoveryPing sweep + ARP on the local network, OS fingerprinting via TTL🔓 Port ScannerCommon ports or custom ranges with banner grabbing📶 WiFi ScannerSSID, BSSID, signal (dBm + %), security, channel, AP vendor📡 Bluetooth ScannerBLE via bleak, classic Bluetooth via pybluez, PowerShell fallback🕵️ Live CaptureReal-time display of TCP / UDP / ICMP / ARP packets via Scapy📊 Full ScanAutomatically chains all 5 modules above with a final summary

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
