#!/bin/bash
# =============================================================================
# Sentient AI - Script de Mise à Jour
# Compatible Linux, macOS & WSL (Root & Non-Root)
# =============================================================================

set -e

# Détermination dynamique du répertoire de l'application
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "====================================================="
echo "🔄 Mise à jour de Sentient AI"
echo "====================================================="

# Vérification des droits d'écriture sur le répertoire
if [ ! -w "$APP_DIR" ] && [ "$EUID" -ne 0 ]; then 
  echo "[!] Veuillez exécuter ce script en tant que root (sudo) car vous n'avez pas les droits d'écriture sur $APP_DIR."
  exit 1
fi

# Détecter si on est sur un système avec systemd
HAS_SYSTEMD=false
if [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

# 1. Mise à jour du code (Git)
echo "[*] Mise à jour de l'application (Git pull)..."
if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR"
    git pull origin main || echo "[!] Impossible de faire le pull. Vérifiez votre connexion ou l'état du dépôt."
else
    echo "[i] Pas de dépôt git détecté dans $APP_DIR. Ignoré."
fi

# 2. Mise à jour des dépendances Python
echo "[*] Mise à jour de l'environnement Python..."
cd "$APP_DIR"
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
    pip install -r requirements.txt --upgrade
else
    echo "[!] Environnement virtuel non détecté."
fi

# 3. Mise à jour des templates Nuclei
echo "[*] Mise à jour de la base de signatures de failles (Nuclei)..."
if command -v nuclei &> /dev/null; then
    nuclei -update-templates || true
elif [ -f "$HOME/.local/bin/nuclei" ]; then
    "$HOME/.local/bin/nuclei" -update-templates || true
else
    echo "[!] Nuclei non détecté dans le PATH."
fi

# 4. Mise à jour du modèle d'IA (Ollama)
echo "[*] Mise à jour du modèle d'IA Llama 3..."
if [ "$HAS_SYSTEMD" = true ]; then
    sudo systemctl start ollama || true
fi

# Configuration des variables GFX si nécessaire
if command -v lspci &>/dev/null; then
    GPU_INFO=$(lspci | grep -i -E 'vga|3d|display')
    if echo "$GPU_INFO" | grep -i -E 'amd|ati' &>/dev/null; then
        if echo "$GPU_INFO" | grep -i 'Strix Halo' &>/dev/null; then
            export HSA_OVERRIDE_GFX_VERSION="11.5.1"
            export HCC_AMDGPU_TARGET=gfx1151
        elif echo "$GPU_INFO" | grep -i -E 'Navi 22|Navi 21|Navi 23|Navi 24|RX 6[0-9]00' &>/dev/null; then
            export HSA_OVERRIDE_GFX_VERSION="10.3.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 1[0-9]|RX 5[0-9]00' &>/dev/null; then
            export HSA_OVERRIDE_GFX_VERSION="10.1.0"
        elif echo "$GPU_INFO" | grep -i -E 'Navi 3[0-9]|RX 7[0-9]00' &>/dev/null; then
            export HSA_OVERRIDE_GFX_VERSION="11.0.0"
        fi
    fi
fi

ollama pull llama3.1:8b || echo "[!] Échec du pull du modèle Llama."

echo "====================================================="
echo "✅ Mise à jour terminée avec succès !"
echo "====================================================="
