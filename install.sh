#!/bin/sh
# ═══════════════════════════════════════════════
#  NetRadar — Installation (Linux / macOS / a-Shell)
# ═══════════════════════════════════════════════

printf "\n"
printf " ███╗   ██╗███████╗████████╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗\n"
printf " ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗\n"
printf " ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║██║  ██║███████║██████╔╝\n"
printf " ██║╚██╗██║██╔══╝     ██║       ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗\n"
printf " ██║ ╚████║███████╗   ██║       ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║\n"
printf " ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n"
printf "\n"
printf " Installation des dependances...\n"
printf " ════════════════════════════════════════════════\n\n"

# ── Vérifier Python ───────────────────────────
if command -v python3 > /dev/null 2>&1; then
    PYTHON=python3
elif command -v python > /dev/null 2>&1; then
    PYTHON=python
else
    printf " [ERREUR] Python introuvable.\n"
    printf "          Sur a-Shell : python3 est deja inclus.\n"
    printf "          Sur Linux   : sudo apt install python3\n"
    exit 1
fi

printf " [OK] Python detecte : $($PYTHON --version)\n\n"

# ── Mettre à jour pip ─────────────────────────
printf " Mise a jour de pip...\n"
$PYTHON -m pip install --upgrade pip --quiet
printf "\n"

# ── Installation des modules ──────────────────
printf " Installation des modules...\n"
printf " ────────────────────────────────────────────────\n"

install_pkg() {
    NUM=$1
    NAME=$2
    PKG=$3
    REQUIRED=$4
    printf " [%s/6] %s...\n" "$NUM" "$NAME"
    if $PYTHON -m pip install "$PKG" --quiet; then
        printf "        OK\n"
    else
        if [ "$REQUIRED" = "required" ]; then
            printf "        ECHEC — module obligatoire !\n"
            exit 1
        else
            printf "        ECHEC (optionnel — certaines fonctions desactivees)\n"
        fi
    fi
}

install_pkg "1" "rich (interface CLI)"       "rich>=13.0.0"      "required"
install_pkg "2" "scapy (scan + capture)"     "scapy>=2.5.0"      "optional"
install_pkg "3" "netifaces (interfaces)"     "netifaces>=0.11.0" "optional"
install_pkg "4" "pywifi (scan WiFi)"         "pywifi>=1.1.12"    "optional"
install_pkg "5" "bleak (Bluetooth BLE)"      "bleak>=0.21.0"     "optional"
install_pkg "6" "python-nmap (detection OS)" "python-nmap>=0.7.1" "optional"

printf "\n ════════════════════════════════════════════════\n"
printf "\n [OK] Installation terminee !\n\n"
printf " NOTE: scapy necessite les droits root pour la capture de paquets.\n"
printf "       Sur a-Shell (iPhone), scapy et pywifi ne sont pas supportes.\n\n"
printf " LANCEMENT:\n"
printf "   python3 netRadar.py           (menu interactif)\n"
printf "   python3 netRadar.py --full    (scan complet)\n"
printf "   python3 netRadar.py --help    (aide)\n\n"
