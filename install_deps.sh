#!/bin/bash

echo "Installation des dépendances pour le PoC Scanner..."

# 1. Détection du gestionnaire de paquets et installation des dépendances système
if command -v apt-get &> /dev/null; then
    echo "Système basé sur Debian/Ubuntu détecté."
    sudo apt-get update
    sudo apt-get install -y nmap wget unzip curl python3-pip python3-venv
    # Dépendances pour WeasyPrint
    sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libjpeg-dev libopenjp2-7-dev libffi-dev

elif command -v dnf &> /dev/null; then
    echo "Système basé sur Fedora/RHEL détecté."
    sudo dnf install -y nmap wget unzip curl python3-pip
    # Dépendances pour WeasyPrint
    sudo dnf install -y pango pango-devel libffi-devel libjpeg-turbo-devel openjpeg2-devel

elif command -v pacman &> /dev/null; then
    echo "Système basé sur Arch Linux détecté."
    sudo pacman -Sy --noconfirm nmap wget unzip curl python-pip
    # Dépendances pour WeasyPrint
    sudo pacman -S --noconfirm pango libffi libjpeg-turbo openjpeg2

else
    echo "[!] Gestionnaire de paquets non supporté automatiquement (apt/dnf/pacman introuvables)."
    echo "Veuillez installer manuellement : nmap, python3, pip, wget, unzip, et les dépendances Pango/Cairo pour WeasyPrint."
fi

# 2. Installation de Nuclei
if ! command -v nuclei &> /dev/null; then
    echo "Installation de Nuclei..."
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip
    unzip -o nuclei_3.2.0_linux_amd64.zip
    sudo mv nuclei /usr/local/bin/
    rm nuclei_3.2.0_linux_amd64.zip
    echo "Nuclei installé."
    # Mise à jour des templates
    nuclei -update-templates
else
    echo "Nuclei est déjà installé."
fi

# 3. Installation de Ollama
if ! command -v ollama &> /dev/null; then
    echo "Installation de Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama est déjà installé."
fi

# 4. Pull du modèle (en arrière plan pour que le script se termine)
echo "Téléchargement de llama3.1:8b (cela peut prendre du temps selon votre connexion)..."
ollama pull llama3.1:8b

echo "Terminé. Pensez à créer votre environnement virtuel (python3 -m venv venv) et faire un pip install -r requirements.txt"
