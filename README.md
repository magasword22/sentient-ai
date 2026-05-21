# 🛡️ Sentient AI

<img src="assets/SentientAIPurple.png" width="180" align="right">

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

Le script d'installation prend en charge automatiquement de nombreux systèmes et architectures :
- **OS supportés** : Linux (Debian, Ubuntu, Mint, Kali, Fedora, RHEL, Rocky, CentOS, Arch Linux, Alpine, openSUSE), macOS et Windows (via WSL).
- **Architectures** : Intel/AMD (`amd64` / `386`) et ARM (`arm64` / `armv6`).
- **Accélération GPU** : Détection automatique des GPU **NVIDIA** (CUDA) et **AMD** (ROCm/Vulkan). Pour les puces graphiques AMD spécifiques comme **Strix Halo** (série Ryzen AI Max) ou RDNA2/3 (RX 6000/7000), le script configure automatiquement les variables d'environnement nécessaires pour forcer la compatibilité d'Ollama.

### Lancement de l'installation

Exécutez simplement la commande suivante dans votre terminal :

```bash
curl -sL https://raw.githubusercontent.com/magasword22/sentient-ai/main/install.sh | bash
```

> [!NOTE]
> - Si exécuté en tant que `root` (ou avec `sudo`), l'application s'installera dans `/opt/sentient` et le CLI sera disponible globalement sous `sentient`.
> - Si exécuté en tant qu'utilisateur standard, l'application s'installera dans `$HOME/.sentient` et le CLI sera placé dans `$HOME/.local/bin/sentient`.

Une fois installé, l'application est accessible à l'adresse :
👉 `http://localhost:8501`

### Gestion de l'application (CLI `sentient`)

Un gestionnaire en ligne de commande est installé pour contrôler facilement l'application en arrière-plan :

```bash
sentient start    # Démarre l'application
sentient stop     # Arrête l'application
sentient status   # Affiche l'état d'exécution
sentient logs     # Affiche les logs en temps réel (Streamlit)
sentient run      # Lance l'interface en mode debug (premier plan)
```

*(Si systemd est absent, comme sur macOS, Alpine ou certains conteneurs/WSL, le CLI basculera de manière transparente sur un système de gestion de processus par fichier PID).*

---

## 🐳 Déploiement avec Docker Compose (Recommandé & Multi-plateforme)

Pour un déploiement instantané sans aucune dépendance système locale (pas besoin d'installer Python, Nmap, Nuclei ou Ollama sur votre machine hôte), vous pouvez utiliser **Docker Compose**. 

### 1. Préparation (Pour une nouvelle machine)
Si vous clonez le dépôt pour la première fois sur un nouveau système, créez les fichiers de base requis pour la persistance :
```bash
touch audits.db report_config.json
```

### 2. Démarrage
Lancez l'application et son instance d'IA locale en arrière-plan :
```bash
docker compose up --build -d
```

L'application web Streamlit est alors directement accessible à l'adresse :
👉 `http://localhost:8501`
Et le moteur Ollama tourne sur `http://localhost:11434`.

### 3. Accélération Matérielle GPU (Optionnel)
Par défaut, l'instance Ollama s'exécute sur CPU pour garantir une compatibilité universelle sur toutes les distributions et architectures. Pour activer l'accélération graphique :
- **GPU Nvidia (CUDA)** : Décommentez le bloc `deploy` dans le fichier `docker-compose.yml`.
- **GPU AMD (ROCm)** : Décommentez l'image `ollama/ollama:rocm`, configurez les variables d'environnement AMD adaptées à votre carte (ex: `HSA_OVERRIDE_GFX_VERSION` pour les architectures comme *Strix Halo*), et passez les périphériques `/dev/kfd` et `/dev/dri`.

---

## 🔄 Mise à jour et Maintenance

Pour mettre à jour l'application, la base de signatures de vulnérabilités Nuclei et le modèle d'IA local (Ollama) :

```bash
# Si installé en mode root / global :
sudo sentient update

# Si installé en mode utilisateur standard :
sentient update
```

---

## 🛠️ Utilisation Manuelle (Pour développeurs)

Si vous souhaitez faire tourner le code manuellement sans le script d'installation :

1. Assurez-vous d'avoir installé Nmap, Nuclei, Python 3.10+ et Ollama.
2. Clonez ce dépôt :
```bash
git clone https://github.com/magasword22/sentient-ai.git
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

## 📋 Feuille de Route & Backlog

Pour suivre l'avancement du projet, les fonctionnalités déjà implémentées (justifications DORA/NIS 2/RGPD, sélections de vulnérabilités multi-catégories) ainsi que les évolutions futures planifiées (hybridation cloud, RAG étendu, scans authentifiés, intégration SAST/DevSecOps), veuillez consulter le fichier [TODO.md](TODO.md).

## 📜 Licence
Développé pour l'orchestration avancée de Red Teaming.
