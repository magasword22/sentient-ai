#!/bin/bash
# =============================================================================
# Sentient AI - Script d'installation des dépendances
# Compatible Debian, Ubuntu, Fedora, RHEL, Arch, Alpine, openSUSE, macOS & WSL
# =============================================================================

set -e

echo "====================================================="
echo "⚙️ Installation des dépendances Sentient AI"
echo "====================================================="

# 1. Détection de l'OS et de l'architecture
OS="$(uname -s)"
case "$OS" in
    Linux*)     OS_TYPE=Linux;;
    Darwin*)    OS_TYPE=macOS;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*) OS_TYPE=Windows;;
    *)          OS_TYPE="UNKNOWN:${OS}"
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH_TYPE="amd64";;
    i386|i686)      ARCH_TYPE="386";;
    aarch64|arm64)  ARCH_TYPE="arm64";;
    armv7l|armv6l)  ARCH_TYPE="armv6";;
    *)              ARCH_TYPE="amd64";;
esac

echo "[*] Système détecté : $OS_TYPE ($ARCH_TYPE)"

# Détection de systemd
HAS_SYSTEMD=false
if [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

# 2. Installation des paquets système
if [ "$OS_TYPE" = "Linux" ]; then
    if command -v apt-get &> /dev/null; then
        echo "[+] Gestionnaire : APT (Debian/Ubuntu)"
        sudo apt-get update -y
        sudo apt-get install -y nmap wget curl git python3 python3-venv python3-pip unzip libpango-1.0-0 libpangoft2-1.0-0 libjpeg-dev libopenjp2-7-dev libffi-dev rustc cargo
    elif command -v dnf &> /dev/null; then
        echo "[+] Gestionnaire : DNF (Fedora/RHEL)"
        sudo dnf install -y nmap wget curl git python3 python3-pip unzip pango pango-devel libffi-devel libjpeg-turbo-devel openjpeg2-devel rust cargo
    elif command -v yum &> /dev/null; then
        echo "[+] Gestionnaire : YUM (CentOS)"
        sudo yum install -y nmap wget curl git python3 python3-pip unzip pango pango-devel libffi-devel libjpeg-turbo-devel openjpeg2-devel rust cargo
    elif command -v pacman &> /dev/null; then
        echo "[+] Gestionnaire : Pacman (Arch)"
        sudo pacman -Sy --noconfirm nmap wget unzip curl git python python-pip pango libffi libjpeg-turbo openjpeg2 rust
    elif command -v apk &> /dev/null; then
        echo "[+] Gestionnaire : APK (Alpine)"
        sudo apk add --no-cache nmap wget curl git python3 python3-dev py3-pip unzip pango-dev libffi-dev jpeg-dev openjpeg-dev g++ rust cargo
    elif command -v zypper &> /dev/null; then
        echo "[+] Gestionnaire : Zypper (openSUSE)"
        sudo zypper install -y nmap wget curl git python3 python3-devel unzip pango pango-devel libffi-devel cairo-devel gdk-pixbuf-devel rust cargo
    else
        echo "[!] Pas de gestionnaire de paquets supporté automatiquement. Installez nmap, python3, pip, wget, unzip, le compilateur Rust (rustc & cargo) et pango/cairo manuellement."
    fi
elif [ "$OS_TYPE" = "macOS" ]; then
    if command -v brew &> /dev/null; then
        echo "[+] Gestionnaire : Homebrew (macOS)"
        brew install nmap wget curl git python3 unzip pango libffi openjpeg rust
    else
        echo "[!] Installez Homebrew ou installez manuellement nmap, python3, pip, wget, unzip, git, pango, libffi et rust."
    fi
fi

# 3. Configuration du GPU (Ollama)
GFX_VER=""
if [ "$OS_TYPE" = "Linux" ] && command -v lspci &>/dev/null; then
    GPU_INFO=$(lspci | grep -i -E 'vga|3d|display')
    if echo "$GPU_INFO" | grep -i -E 'amd|ati' &>/dev/null; then
        if echo "$GPU_INFO" | grep -i 'Strix Halo' &>/dev/null; then
            GFX_VER="11.5.1"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 22|Navi 21|Navi 23|Navi 24|RX 6[0-9]00' &>/dev/null; then
            GFX_VER="10.3.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 1[0-9]|RX 5[0-9]00' &>/dev/null; then
            GFX_VER="10.1.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 3[0-9]|RX 7[0-9]00' &>/dev/null; then
            GFX_VER="11.0.0"
        fi
    fi
fi

# 4. Installation de Nuclei
if ! command -v nuclei &> /dev/null; then
    echo "[*] Installation de Nuclei..."
    NUCLEI_OS="linux"
    if [ "$OS_TYPE" = "macOS" ]; then
        NUCLEI_OS="macOS"
    fi
    
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_${NUCLEI_OS}_${ARCH_TYPE}.zip"
    
    TMP_DIR=$(mktemp -d)
    if wget "$NUCLEI_URL" -O "$TMP_DIR/nuclei.zip"; then
        unzip -o "$TMP_DIR/nuclei.zip" -d "$TMP_DIR"
        
        if [ "$EUID" -eq 0 ]; then
            mv "$TMP_DIR/nuclei" /usr/local/bin/
            echo "[+] Nuclei installé dans /usr/local/bin/"
        else
            mkdir -p "$HOME/.local/bin"
            mv "$TMP_DIR/nuclei" "$HOME/.local/bin/"
            export PATH="$HOME/.local/bin:$PATH"
            echo "[+] Nuclei installé dans $HOME/.local/bin/"
        fi
    else
        echo "[!] Échec du téléchargement. Essai avec go..."
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        fi
    fi
    rm -rf "$TMP_DIR"
else
    echo "[+] Nuclei est déjà installé."
fi

# Mise à jour des templates Nuclei
if command -v nuclei &> /dev/null; then
    nuclei -update-templates || true
elif [ -f "$HOME/.local/bin/nuclei" ]; then
    "$HOME/.local/bin/nuclei" -update-templates || true
fi

# 5. Installation d'Ollama
if ! command -v ollama &> /dev/null; then
    echo "[*] Installation d'Ollama..."
    if [ "$OS_TYPE" = "Linux" ]; then
        curl -fsSL https://ollama.com/install.sh | sh
    elif [ "$OS_TYPE" = "macOS" ] && command -v brew &> /dev/null; then
        brew install --cask ollama || brew install ollama
    fi
else
    echo "[+] Ollama est déjà installé."
fi

# Configuration GPU pour le service Ollama
OLLAMA_PID=""
if [ "$HAS_SYSTEMD" = true ]; then
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
    echo "[*] Démarrage temporaire d'Ollama pour le pull du modèle..."
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

# Pull du modèle
echo "[*] Téléchargement de llama3.1:8b..."
ollama pull llama3.1:8b || echo "[!] Échec du pull. Assurez-vous qu'Ollama fonctionne."

if [ -n "$OLLAMA_PID" ]; then
    kill "$OLLAMA_PID" || true
fi

echo "====================================================="
echo "✅ Dépendances installées avec succès !"
echo "====================================================="
