#!/bin/bash
# =============================================================================
# Sentient AI - Installateur Automatisé Multi-Système & Multi-Distro
# Compatible Debian, Ubuntu, Fedora, RHEL, Arch, Alpine, openSUSE, macOS & WSL
# =============================================================================

set -e

echo "====================================================="
echo "🛡️ Bienvenue dans l'installateur Sentient AI"
echo "====================================================="

# 1. Détection de l'OS
OS="$(uname -s)"
case "$OS" in
    Linux*)     OS_TYPE=Linux;;
    Darwin*)    OS_TYPE=macOS;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*) OS_TYPE=Windows;;
    *)          OS_TYPE="UNKNOWN:${OS}"
esac

# 2. Détection de l'architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH_TYPE="amd64";;
    i386|i686)      ARCH_TYPE="386";;
    aarch64|arm64)  ARCH_TYPE="arm64";;
    armv7l|armv6l)  ARCH_TYPE="armv6";;
    *)              ARCH_TYPE="amd64";; # Fallback
esac

echo "[*] Système détecté : $OS_TYPE ($ARCH_TYPE)"

# Vérification des droits root uniquement sur Linux si nécessaire
# (Sur macOS, Homebrew interdit l'exécution sous root/sudo, donc on n'impose pas root)
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

# Choix du répertoire d'installation
if [ "$IS_ROOT" = true ]; then
    APP_DIR="/opt/sentient"
else
    APP_DIR="$HOME/.sentient"
fi
echo "[*] Répertoire d'installation cible : $APP_DIR"

# Détection de systemd
HAS_SYSTEMD=false
if [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

# 3. Installation des dépendances système selon l'OS / gestionnaire
echo "[*] Étape 1 : Installation des dépendances système..."

if [ "$OS_TYPE" = "Linux" ]; then
    if command -v apt-get &> /dev/null; then
        echo "[+] Gestionnaire de paquets : APT (Debian/Ubuntu/Mint/Kali)"
        sudo apt-get update -y
        sudo apt-get install -y nmap wget curl git python3 python3-venv python3-pip unzip libpango-1.0-0 libpangoft2-1.0-0 libjpeg-dev libopenjp2-7-dev libffi-dev
    elif command -v dnf &> /dev/null; then
        echo "[+] Gestionnaire de paquets : DNF (Fedora/RHEL/Rocky/Alma)"
        sudo dnf install -y nmap wget curl git python3 python3-pip unzip pango pango-devel libffi-devel libjpeg-turbo-devel openjpeg2-devel
    elif command -v yum &> /dev/null; then
        echo "[+] Gestionnaire de paquets : YUM (CentOS/RHEL)"
        sudo yum install -y nmap wget curl git python3 python3-pip unzip pango pango-devel libffi-devel libjpeg-turbo-devel openjpeg2-devel
    elif command -v pacman &> /dev/null; then
        echo "[+] Gestionnaire de paquets : Pacman (Arch Linux/Manjaro)"
        sudo pacman -Sy --noconfirm nmap wget unzip curl git python python-pip pango libffi libjpeg-turbo openjpeg2
    elif command -v apk &> /dev/null; then
        echo "[+] Gestionnaire de paquets : APK (Alpine Linux)"
        sudo apk add --no-cache nmap wget curl git python3 python3-dev py3-pip unzip pango-dev libffi-dev jpeg-dev openjpeg-dev g++
    elif command -v zypper &> /dev/null; then
        echo "[+] Gestionnaire de paquets : Zypper (openSUSE/SUSE)"
        sudo zypper install -y nmap wget curl git python3 python3-devel unzip pango pango-devel libffi-devel cairo-devel gdk-pixbuf-devel
    else
        echo "[!] Gestionnaire de paquets non reconnu automatiquement sur Linux."
        echo "Veuillez vous assurer que nmap, python3, pip, wget, unzip et les dépendances Pango/Cairo sont installés."
    fi
elif [ "$OS_TYPE" = "macOS" ]; then
    if command -v brew &> /dev/null; then
        echo "[+] Gestionnaire de paquets : Homebrew (macOS)"
        brew install nmap wget curl git python3 unzip pango libffi openjpeg
    else
        echo "[!] Homebrew n'est pas détecté. Veuillez installer Homebrew (https://brew.sh/) ou installer manuellement les dépendances :"
        echo "nmap, python3, wget, curl, unzip, git, pango, libffi, openjpeg"
    fi
elif [ "$OS_TYPE" = "Windows" ]; then
    echo "[!] Exécution sous Windows (MSYS/Cygwin/Git Bash) détectée."
    echo "[!] Pour de meilleures performances et compatibilité, utilisez WSL (Windows Subsystem for Linux)."
    echo "[!] Le script va tenter de continuer mais certaines étapes peuvent nécessiter une installation manuelle."
else
    echo "[!] Système d'exploitation '$OS_TYPE' non supporté automatiquement."
fi

# 4. Détection et configuration du GPU (Ollama)
echo "[*] Étape 2 : Détection et configuration du GPU..."
HAS_GPU=false
GFX_VER=""
if [ "$OS_TYPE" = "Linux" ] && command -v lspci &>/dev/null; then
    GPU_INFO=$(lspci | grep -i -E 'vga|3d|display')
    if echo "$GPU_INFO" | grep -i 'nvidia' &>/dev/null; then
        echo "[+] GPU NVIDIA détecté. Ollama utilisera CUDA automatiquement."
        HAS_GPU=true
    elif echo "$GPU_INFO" | grep -i -E 'amd|ati' &>/dev/null; then
        echo "[+] GPU AMD détecté."
        HAS_GPU=true
        if echo "$GPU_INFO" | grep -i 'Strix Halo' &>/dev/null; then
            echo "[i] GPU AMD Strix Halo détecté. Configuration de HSA_OVERRIDE_GFX_VERSION=11.5.1"
            GFX_VER="11.5.1"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 22|Navi 21|Navi 23|Navi 24|RX 6[0-9]00' &>/dev/null; then
            echo "[i] GPU AMD RDNA2 (Série RX 6000) détecté. Configuration de HSA_OVERRIDE_GFX_VERSION=10.3.0"
            GFX_VER="10.3.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 1[0-9]|RX 5[0-9]00' &>/dev/null; then
            echo "[i] GPU AMD RDNA1 (Série RX 5000) détecté. Configuration de HSA_OVERRIDE_GFX_VERSION=10.1.0"
            GFX_VER="10.1.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 3[0-9]|RX 7[0-9]00' &>/dev/null; then
            echo "[i] GPU AMD RDNA3 (Série RX 7000) détecté. Configuration de HSA_OVERRIDE_GFX_VERSION=11.0.0"
            GFX_VER="11.0.0"
        fi
    fi
fi

# 5. Installation de Nuclei
echo "[*] Étape 3 : Installation de Nuclei..."
if ! command -v nuclei &> /dev/null; then
    # Déterminer le nom de l'OS pour le binaire nuclei (macOS utilise macOS, Linux utilise linux)
    NUCLEI_OS="linux"
    if [ "$OS_TYPE" = "macOS" ]; then
        NUCLEI_OS="macOS"
    fi
    
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_${NUCLEI_OS}_${ARCH_TYPE}.zip"
    echo "[*] Téléchargement de Nuclei depuis $NUCLEI_URL ..."
    
    if wget "$NUCLEI_URL" -O nuclei.zip; then
        unzip -o nuclei.zip
        rm nuclei.zip
        
        # Installation du binaire
        if [ "$IS_ROOT" = true ]; then
            mv nuclei /usr/local/bin/
            echo "[+] Nuclei installé dans /usr/local/bin/"
        else
            mkdir -p "$HOME/.local/bin"
            mv nuclei "$HOME/.local/bin/"
            export PATH="$HOME/.local/bin:$PATH"
            echo "[+] Nuclei installé dans $HOME/.local/bin/"
        fi
    else
        echo "[!] Échec du téléchargement de Nuclei pour $NUCLEI_OS / $ARCH_TYPE. Essai d'installation via go..."
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        else
            echo "[!] Go n'est pas installé. Veuillez installer Nuclei manuellement (https://github.com/projectdiscovery/nuclei)."
        fi
    fi
else
    echo "[+] Nuclei est déjà installé."
fi

# Mise à jour des templates Nuclei
if command -v nuclei &> /dev/null; then
    nuclei -update-templates || true
elif [ -f "$HOME/.local/bin/nuclei" ]; then
    "$HOME/.local/bin/nuclei" -update-templates || true
fi

# 6. Installation d'Ollama
echo "[*] Étape 4 : Installation de Ollama..."
if ! command -v ollama &> /dev/null; then
    if [ "$OS_TYPE" = "Linux" ]; then
        curl -fsSL https://ollama.com/install.sh | sh
        echo "[+] Ollama installé."
    elif [ "$OS_TYPE" = "macOS" ]; then
        if command -v brew &> /dev/null; then
            brew install --cask ollama || brew install ollama
        else
            echo "[i] macOS détecté sans Homebrew. Veuillez télécharger Ollama depuis https://ollama.com/"
        fi
    else
        echo "[i] Veuillez installer Ollama manuellement depuis https://ollama.com/"
    fi
else
    echo "[+] Ollama est déjà installé."
fi

# Démarrage d'Ollama temporaire ou permanent pour pouvoir pull le modèle
OLLAMA_PID=""
if [ "$HAS_SYSTEMD" = true ]; then
    # Appliquer l'override GPU si AMD détecté
    if [ -n "$GFX_VER" ]; then
        echo "[*] Configuration de l'override AMD pour le service Ollama..."
        sudo mkdir -p /etc/systemd/system/ollama.service.d
        cat << EOF | sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null
[Service]
Environment="HSA_OVERRIDE_GFX_VERSION=$GFX_VER"
EOF
        if [ "$GFX_VER" = "11.5.1" ]; then
            cat << EOF | sudo tee -a /etc/systemd/system/ollama.service.d/override.conf > /dev/null
Environment="HCC_AMDGPU_TARGET=gfx1151"
EOF
        fi
        sudo systemctl daemon-reload
    fi
    sudo systemctl enable ollama || true
    sudo systemctl start ollama || true
else
    # Lancement manuel en tâche de fond pour le pull
    echo "[*] Lancement temporaire d'Ollama en arrière-plan..."
    if [ -n "$GFX_VER" ]; then
        export HSA_OVERRIDE_GFX_VERSION="$GFX_VER"
        if [ "$GFX_VER" = "11.5.1" ]; then
            export HCC_AMDGPU_TARGET=gfx1151
        fi
    fi
    ollama serve &>/dev/null &
    OLLAMA_PID=$!
    sleep 5
fi

echo "[*] Étape 5 : Téléchargement du Modèle IA (llama3.1:8b)..."
echo "Cela peut prendre un certain temps selon votre connexion internet."
ollama pull llama3.1:8b || echo "[!] Échec du pull du modèle. Assurez-vous qu'Ollama tourne correctement."

# Arrêter l'ollama temporaire si démarré manuellement
if [ -n "$OLLAMA_PID" ]; then
    kill "$OLLAMA_PID" || true
fi

# 7. Configuration de l'application
echo "[*] Étape 6 : Configuration de l'application dans $APP_DIR..."
mkdir -p $APP_DIR

if command -v rsync &> /dev/null; then
    rsync -av --exclude='audits.db' --exclude='reports' --exclude='rag_db' --exclude='venv' --exclude='.git' ./ $APP_DIR/
else
    cp -rf *.py *.sh requirements.txt sentient.service $APP_DIR/
fi

cd $APP_DIR

# Configuration de l'environnement virtuel Python
echo "[*] Étape 7 : Configuration de l'environnement virtuel Python..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install "setuptools<70"
pip install -r requirements.txt

# 8. Création du script CLI Sentient
CLI_PATH="/usr/local/bin/sentient"
if [ "$IS_ROOT" = false ]; then
    mkdir -p "$HOME/.local/bin"
    CLI_PATH="$HOME/.local/bin/sentient"
fi

echo "[*] Configuration du gestionnaire CLI Sentient dans $CLI_PATH..."

cat << 'EOF' > "$CLI_PATH"
#!/bin/bash

# Configuration
APP_DIR="INSTALL_DIR_PLACEHOLDER"
PID_FILE="$APP_DIR/sentient.pid"
LOG_FILE="$APP_DIR/sentient.log"

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

# Détecter si systemd est dispo pour cette installation
HAS_SYSTEMD=false
if [ -d /run/systemd/system ] && [ "INSTALL_DIR_PLACEHOLDER" = "/opt/sentient" ]; then
    HAS_SYSTEMD=true
fi

case $COMMAND in
    start)
        echo "[*] Démarrage de Sentient AI..."
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo systemctl start sentient
            echo "[+] Service démarré. (http://localhost:8501)"
        else
            if [ -f "$PID_FILE" ]; then
                PID=$(cat "$PID_FILE")
                if kill -0 "$PID" &>/dev/null; then
                    echo "[+] Sentient AI est déjà démarré (PID: $PID, http://localhost:8501)"
                    exit 0
                fi
            fi
            cd "$APP_DIR"
            source venv/bin/activate
            nohup streamlit run app.py --server.port 8501 --server.address 0.0.0.0 > "$LOG_FILE" 2>&1 &
            echo $! > "$PID_FILE"
            echo "[+] Service démarré en tâche de fond (http://localhost:8501)."
        fi
        ;;
    stop)
        echo "[*] Arrêt de Sentient AI..."
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo systemctl stop sentient
            echo "[-] Service arrêté."
        else
            if [ -f "$PID_FILE" ]; then
                PID=$(cat "$PID_FILE")
                kill "$PID" || true
                rm -f "$PID_FILE"
                echo "[-] Service arrêté."
            else
                echo "[!] Aucun fichier PID trouvé. L'application ne semble pas tourner."
            fi
        fi
        ;;
    restart)
        echo "[*] Redémarrage de Sentient AI..."
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo systemctl restart sentient
            echo "[+] Service redémarré."
        else
            $0 stop
            sleep 2
            $0 start
        fi
        ;;
    status)
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo systemctl status sentient --no-pager
        else
            if [ -f "$PID_FILE" ]; then
                PID=$(cat "$PID_FILE")
                if kill -0 "$PID" &>/dev/null; then
                    echo "[+] Sentient AI est en cours d'exécution (PID: $PID)"
                    echo "    Accessible sur : http://localhost:8501"
                else
                    echo "[-] Sentient AI n'est pas en cours d'exécution (PID orphelin trouvé)."
                fi
            else
                echo "[-] Sentient AI est arrêté."
            fi
        fi
        ;;
    logs)
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo journalctl -u sentient -f
        else
            if [ -f "$LOG_FILE" ]; then
                tail -f "$LOG_FILE"
            else
                echo "[-] Aucun fichier de log trouvé à l'emplacement $LOG_FILE"
            fi
        fi
        ;;
    update)
        if [ "$HAS_SYSTEMD" = true ]; then
            sudo /opt/sentient/update.sh
        else
            "$APP_DIR/update.sh"
        fi
        ;;
    run)
        cd "$APP_DIR"
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

# Remplacer INSTALL_DIR_PLACEHOLDER par la valeur réelle
if command -v perl &> /dev/null; then
    perl -pi -e "s|INSTALL_DIR_PLACEHOLDER|$APP_DIR|g" "$CLI_PATH"
else
    # sed fallback
    sed -i "s|INSTALL_DIR_PLACEHOLDER|$APP_DIR|g" "$CLI_PATH" || sed -i "" "s|INSTALL_DIR_PLACEHOLDER|$APP_DIR|g" "$CLI_PATH"
fi

chmod +x "$CLI_PATH"

# 9. Configuration du Service en arrière-plan (Systemd) - Optionnel
if [ "$HAS_SYSTEMD" = true ]; then
    echo "[*] Étape 8 : Configuration du service systemd..."
    
    # Vérification SELinux
    if command -v getenforce &> /dev/null && [ "$(getenforce)" = "Enforcing" ]; then
        echo ""
        echo "[!] SELinux est activé et pourrait bloquer le démarrage de l'application."
        echo "[*] Application du label de sécurité (bin_t)..."
        chcon -R -t bin_t $APP_DIR/venv/bin/ || true
    fi
    
    if [ -f "$APP_DIR/sentient.service" ]; then
        sudo cp $APP_DIR/sentient.service /etc/systemd/system/
        sudo systemctl daemon-reload
        sudo systemctl enable sentient
        sudo systemctl restart sentient
        echo "[+] Service Sentient activé sous systemd."
    fi
else
    echo "[i] Systemd non détecté ou non-root. L'application démarrera manuellement ou via les commandes CLI."
fi

echo "====================================================="
echo "✅ Installation terminée avec succès !"
echo "====================================================="
echo "L'application est prête à être exécutée."
if [ "$HAS_SYSTEMD" = true ]; then
    echo "Vous pouvez contrôler le service système avec :"
    echo "  sentient start | stop | status | logs"
else
    echo "Vous pouvez contrôler l'application en arrière-plan avec :"
    echo "  $CLI_PATH start | stop | status | logs"
fi
echo ""
echo "L'interface est accessible sur : http://localhost:8501"
echo "====================================================="
