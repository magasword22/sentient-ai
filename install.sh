#!/bin/bash
# =============================================================================
# VulnShield AI - Installateur Automatisé
# Compatible Debian / Ubuntu
# =============================================================================

set -e

echo "====================================================="
echo "🛡️ Bienvenue dans l'installateur VulnShield AI"
echo "====================================================="

# 1. Vérification des droits root
if [ "$EUID" -ne 0 ]; then 
  echo "[!] Veuillez exécuter ce script en tant que root (sudo ./install.sh)"
  exit 1
fi

echo "[*] Étape 1 : Mise à jour du système et dépendances système..."
apt-get update -y
apt-get install -y nmap wget curl git python3 python3-venv python3-pip unzip

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
APP_DIR="/opt/vulnshield"
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

# Création d'un exécutable rapide
cat << 'EOF' > /usr/local/bin/vulnshield
#!/bin/bash
cd /opt/vulnshield
source venv/bin/activate
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
EOF

chmod +x /usr/local/bin/vulnshield

# 5. Configuration du Service en arrière-plan (Systemd)
echo "[*] Étape 7 : Configuration du service système..."
if [ -f "$APP_DIR/vulnshield.service" ]; then
    cp $APP_DIR/vulnshield.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable vulnshield
    systemctl restart vulnshield
    echo "[+] Service VulnShield activé. Il démarrera tout seul à chaque reboot."
fi

echo "====================================================="
echo "✅ Installation terminée avec succès !"
echo "====================================================="
echo "L'application tourne désormais en tâche de fond."
echo "Vous pouvez vérifier son statut avec : systemctl status vulnshield"
echo ""
echo "L'interface est accessible sur : http://<votre-ip>:8501"
echo "====================================================="
