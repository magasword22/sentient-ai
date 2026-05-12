#!/bin/bash
# =============================================================================
# VulnShield AI - Script de Mise à Jour
# =============================================================================

set -e

APP_DIR="/opt/vulnshield"

echo "====================================================="
echo "🔄 Mise à jour de VulnShield AI"
echo "====================================================="

if [ "$EUID" -ne 0 ]; then 
  echo "[!] Veuillez exécuter ce script en tant que root (sudo vulnshield-update)"
  exit 1
fi

# 1. Mise à jour du code (Git)
echo "[*] Mise à jour de l'application (Git pull)..."
if [ -d "$APP_DIR/.git" ]; then
    cd $APP_DIR
    git pull origin main
else
    echo "[i] Pas de dépôt git détecté dans $APP_DIR. Ignoré."
fi

# 2. Mise à jour des dépendances Python
echo "[*] Mise à jour de l'environnement Python..."
cd $APP_DIR
source venv/bin/activate
pip install -r requirements.txt --upgrade

# 3. Mise à jour des templates Nuclei (Très important pour les failles 0-day)
echo "[*] Mise à jour de la base de signatures de failles (Nuclei)..."
nuclei -update-templates

# 4. Mise à jour du modèle d'IA (Ollama)
echo "[*] Mise à jour du modèle d'IA Llama 3..."
systemctl start ollama || true
ollama pull llama3.1:8b

echo "====================================================="
echo "✅ Mise à jour terminée avec succès !"
echo "====================================================="
