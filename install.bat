@echo off
chcp 65001 >nul
title NetRadar — Installation

echo.
echo  ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
echo  ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
echo  ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝
echo  ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
echo  ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
echo  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
echo.
echo  Installation des dependances...
echo  ════════════════════════════════════════════════
echo.

:: Vérifier Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERREUR] Python n'est pas installe ou pas dans le PATH.
    echo  Telechargez-le sur: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  [OK] Python detecte
echo.

:: Mettre à jour pip
echo  Mise a jour de pip...
python -m pip install --upgrade pip --quiet

echo.
echo  Installation des modules requis...
echo  ────────────────────────────────────────────────

:: Requis
echo  [1/6] rich (interface CLI)...
pip install rich>=13.0.0 --quiet && echo      OK || echo      ECHEC

:: Optionnels
echo  [2/6] scapy (scan avance + capture)...
pip install scapy>=2.5.0 --quiet && echo      OK || echo      ECHEC (optionnel)

echo  [3/6] netifaces (interfaces reseau)...
pip install netifaces>=0.11.0 --quiet && echo      OK || echo      ECHEC (optionnel)

echo  [4/6] pywifi (scan WiFi)...
pip install pywifi>=1.1.12 --quiet && echo      OK || echo      ECHEC (optionnel)

echo  [5/6] bleak (Bluetooth BLE)...
pip install bleak>=0.21.0 --quiet && echo      OK || echo      ECHEC (optionnel)

echo  [6/6] python-nmap (detection OS)...
pip install python-nmap>=0.7.1 --quiet && echo      OK || echo      ECHEC (optionnel)

echo.
echo  ════════════════════════════════════════════════
echo.
echo  Installation terminee !
echo.
echo  NOTE: Pour la capture de paquets (scapy), installez Npcap:
echo        https://npcap.com/#download
echo.
echo  LANCEMENT:
echo    python netRadar.py            (menu interactif)
echo    python netRadar.py --full     (scan complet)
echo    python netRadar.py --help     (aide)
echo.
echo  CONSEIL: Lancez en tant qu'Administrateur pour les fonctions avancees.
echo.
pause
