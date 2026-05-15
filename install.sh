#!/bin/bash
# =============================================================================
# Sentient AI - Installateur Automatisé
# Compatible Debian / Ubuntu
# =============================================================================

set -e

echo "====================================================="
echo "🛡️ Bienvenue dans l'installateur Sentient AI"
echo "====================================================="

# 1. Vérification des droits root
if [ "$EUID" -ne 0 ]; then 
  echo "[!] Veuillez exécuter ce script en tant que root (sudo ./install.sh)"
  exit 1
fi

echo "[*] Étape 1 : Mise à jour du système et dépendances système..."
if command -v apt-get &> /dev/null; then
    apt-get update -y
    apt-get install -y nmap wget curl git python3 python3-venv python3-pip unzip
elif command -v dnf &> /dev/null; then
    dnf install -y nmap wget curl git python3 python3-pip unzip
    # Note: python3-venv n'est pas toujours séparé sur Fedora, pip l'est.
else
    echo "[!] Gestionnaire de paquets non reconnu (ni apt, ni dnf). Veuillez installer les dépendances manuellement."
fi

# 2. Installation de Go et Nuclei
echo "[*] Étape 2 : Installation de Nuclei..."
if ! command -v nuclei &> /dev/null; then
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip -O nuclei.zip
    unzip nuclei.zip
    mv nuclei /usr/local/bin/
    rm nuclei.zip
    echo "[+] Nuclei installé avec succès."
else
    echo "[+] Nuclei est déjà installé."
fi

# Mise à jour initiale des templates
nuclei -update-templates

# 3. Installation d'Ollama
echo "[*] Étape 3 : Installation d'Ollama (Moteur d'IA Local)..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
    echo "[+] Ollama installé avec succès."
else
    echo "[+] Ollama est déjà installé."
fi

# Démarrage d'Ollama en arrière-plan pour pull le modèle
systemctl enable ollama
systemctl start ollama

echo "[*] Étape 4 : Téléchargement du Modèle IA (llama3.1:8b)..."
echo "Cela peut prendre un certain temps selon votre connexion internet."
ollama pull llama3.1:8b

# 4. Configuration de l'application
APP_DIR="/opt/sentient"
echo "[*] Étape 5 : Installation de l'application dans $APP_DIR..."

if [ ! -d "$APP_DIR" ]; then
    # Dans un vrai scénario, on ferait un git clone ici.
    # Pour le moment on copie le dossier actuel
    mkdir -p $APP_DIR
    cp -r ./* $APP_DIR/
fi

cd $APP_DIR

# Création de l'environnement virtuel
echo "[*] Étape 6 : Configuration de l'environnement Python..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install setuptools<70
pip install -r requirements.txt

# Création d'un exécutable CLI (Gestionnaire)
cat << 'EOF' > /usr/local/bin/sentient
#!/bin/bash

COMMAND=$1

function show_help() {
    echo "🛡️ Sentient AI - CLI Manager"
    echo "Usage: sentient [commande]"
    echo ""
    echo "Commandes :"
    echo "  start   : Démarrer l'application en tâche de fond"
    echo "  stop    : Arrêter l'application"
    echo "  restart : Redémarrer l'application"
    echo "  status  : Voir si l'application tourne"
    echo "  logs    : Afficher les logs en temps réel (Ctrl+C pour quitter)"
    echo "  update  : Mettre à jour l'application et les modèles"
    echo "  run     : Lancer l'application dans ce terminal (Mode Debug)"
    echo ""
}

if [ -z "$COMMAND" ] || [ "$COMMAND" == "help" ]; then
    show_help
    exit 0
fi

case $COMMAND in
    start)
        echo "[*] Démarrage de Sentient AI..."
        sudo systemctl start sentient
        echo "[+] Service démarré. (http://localhost:8501)"
        ;;
    stop)
        echo "[*] Arrêt de Sentient AI..."
        sudo systemctl stop sentient
        echo "[-] Service arrêté."
        ;;
    restart)
        echo "[*] Redémarrage..."
        sudo systemctl restart sentient
        echo "[+] Service redémarré."
        ;;
    status)
        sudo systemctl status sentient --no-pager
        ;;
    logs)
        sudo journalctl -u sentient -f
        ;;
    update)
        sudo /opt/sentient/update.sh
        ;;
    run)
        cd /opt/sentient
        source venv/bin/activate
        streamlit run app.py --server.port 8501 --server.address 0.0.0.0
        ;;
    *)
        echo "[!] Commande inconnue: $COMMAND"
        show_help
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/sentient

# 5. Configuration du Service en arrière-plan (Systemd)
echo "[*] Étape 7 : Configuration du service système..."
if [ -f "$APP_DIR/sentient.service" ]; then
    cp $APP_DIR/sentient.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentient
    systemctl restart sentient
    echo "[+] Service Sentient activé. Il démarrera tout seul à chaque reboot."
fi

echo "====================================================="
echo "✅ Installation terminée avec succès !"
echo "====================================================="
echo "L'application tourne désormais en tâche de fond."
echo "Vous pouvez vérifier son statut avec : systemctl status sentient"
echo ""
echo "L'interface est accessible sur : http://<votre-ip>:8501"
echo "====================================================="
