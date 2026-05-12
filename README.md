# 🛡️ Sentient AI

<img src="assets/logo.png" width="180" align="right">

**Sentient AI** est une plateforme d'audit de sécurité automatisée (PTaaS - Penetration Testing as a Service), propulsée par une architecture d'Agents d'Intelligence Artificielle (CrewAI) fonctionnant à **100% en local** (Ollama).

Elle combine la puissance de découverte réseau de **Nmap** et de **Nuclei** avec les capacités de raisonnement de modèles LLM de dernière génération (ex: Llama 3) pour générer des rapports de pentest exécutifs et sans faux positifs.

![Sentient AI](https://img.shields.io/badge/Status-Production%20Ready-success)
![LLM](https://img.shields.io/badge/AI-Ollama%20%7C%20Llama%203-blue)

## 🚀 Fonctionnalités Principales

- **Orchestration Agentique (CrewAI)** : Deux agents IA (Analyste SOC & Lead Pentester) discutent et filtrent les résultats bruts des scanners.
- **Enrichissement Web Dynamique** : L'IA effectue ses propres recherches Web pour trouver des Preuves de Concept (PoC) publiques ou des exploits GitHub en temps réel.
- **RAG (Retrieval-Augmented Generation)** : Ingestion de vos propres documents de sécurité (ISO 27001, guides ANSSI) pour dicter à l'IA comment formuler les recommandations.
- **100% On-Premise / Local** : Vos logs de vulnérabilités ne quittent jamais votre machine.
- **Export B2B** : Génération de rapports PDF complets et connecteur API natif vers **DefectDojo**.
- **Scans Hautement Agressifs** : Support complet des scripts Nmap Vuln (`--script vuln`) et des templates agressifs Nuclei (Default-logins, Exposures, Misconfigs).

---

## 💻 Installation Rapide (Automatisée)

Sur une machine Debian/Ubuntu avec accès Internet, tapez simplement cette commande pour installer l'application complète, configurer les dépendances (Nmap, Nuclei, Python), et installer le modèle IA local :

```bash
curl -sL https://raw.githubusercontent.com/magasword22/sentient-ai/main/install.sh | sudo bash
```

Une fois installé, l'application est accessible depuis n'importe quel navigateur à l'adresse :
👉 `http://localhost:8501`

*(Si la machine est sur votre réseau, remplacez `localhost` par son IP locale).*

---

## 🔄 Mise à jour et Maintenance

La cybersécurité évolue vite. Pour mettre à jour l'application, les templates de failles 0-day de Nuclei, et le modèle d'IA, exécutez le script de mise à jour inclus :

```bash
sudo /opt/sentient/update.sh
```

---

## 🛠️ Utilisation Manuelle (Pour développeurs)

Si vous souhaitez faire tourner le code manuellement sans le script d'installation :

1. Assurez-vous d'avoir installé Nmap, Nuclei, Python 3.10+ et Ollama.
2. Clonez ce dépôt :
```bash
git clone https://github.com/VOTRE_NOM_GITHUB/sentient-ai.git
cd sentient-ai
```
3. Créez votre environnement et installez les prérequis :
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
4. Lancez l'interface web :
```bash
streamlit run app.py
```

## 📜 Licence
Développé pour l'orchestration avancée de Red Teaming.
