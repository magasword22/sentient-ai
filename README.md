# 🛡️ Sentient AI

<img src="assets/SentientAIPurple.png" width="180" align="right">

**Sentient AI** est une plateforme d'audit de sécurité autonome (PTaaS — Penetration Testing as a Service), propulsée par une architecture d'Agents IA (CrewAI) et fonctionnant à 100% en local ou avec des LLM cloud (DeepSeek, OpenAI, Anthropic, Groq, Mistral).

📖 [Documentation Complète](DOCUMENTATION.md) — [Feuille de Route](TODO.md)

![Status](https://img.shields.io/badge/Status-Production%20Ready-success)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%7C%20DeepSeek%20%7C%20OpenAI%20%7C%20Mistral-blue)
![Architecture](https://img.shields.io/badge/Architecture-FastAPI%20%2B%20SPA%20Vanilla%20JS-purple)
![Docker](https://img.shields.io/badge/Docker-Ready-brightgreen)

---

## 🚀 Fonctionnalités

### 🔬 Scan & Découverte
- **Nmap** : Top 1000 / Fast / Full 65535 ports, détection OS, scripts vuln, évasion pare-feu (fragmentation, leurres, MAC spoofing)
- **Nuclei** : 10+ catégories de templates (CVE, default-login, exposure, misconfig, injections, RCE, SSL, DNS, réseau...)
- **Recon** : Subfinder (sous-domaines), Gobuster (répertoires)
- **SAST** : Semgrep + Bandit pour analyse statique de code
- **Trivy** : Scan de vulnérabilités conteneurs Docker / filesystem

### 🧠 IA & Analyse
- **CrewAI Multi-Agents** : Analyst SOC, Lead Pentester, Exploit Validator, Blue Team Defender, Traducteur
- **RAG (Retrieval-Augmented Generation)** : ChromaDB + 4 standards pré-intégrés (ANSSI, CIS Benchmarks, OWASP Top 10, Kernel Exploits)
- **6 fournisseurs LLM** : Ollama (local), DeepSeek, OpenAI, Anthropic, Groq, Mistral
- **Recherche Web Dynamique** : L'IA cherche des PoC publiques en temps réel
- **Rapports PDF White-Label** : Personnalisation logo, couleurs, nom d'entreprise, multilingue

### 🖥️ Audits Système
- **PrivEsc Multi-OS** : Audit SSH Linux/macOS/Windows — SUID, capabilities, sudo, kernel exploits, Docker escape
- **Coffre à PoC** : Génération de scripts de détection inoffensifs par CVE
- **Analyse ROI** : Calculateur de risque financier (DORA/NIS 2/RGPD/PCI-DSS)

### 🛰️ Architecture Distribuée
- **Sondes légères** (`sentient_agent.py`) : déploiement sur VPS distant, scan local, retour JSON
- **Monitoring temps réel** : heartbeat automatique, statut online/offline, scan actif
- **WebSocket** : progression live avec logs des subprocess en streaming

### 🔒 Sécurité & Conformité
- **100% On-Premise** : aucune donnée ne quitte votre infrastructure
- **RBAC** : rôles admin/client, gestion des utilisateurs
- **Secrets protégés** : les clés API et mots de passe ne quittent jamais votre machine
- **Sondes authentifiées** : token Bearer, scans HTTP autorisés
- **Pare-feu UFW** : ports contrôlés, SSH sécurisé

### 🎨 Interface
- **SPA Vanilla JS** : zéro dépendance npm, < 700 lignes de HTML/CSS/JS
- **3 thèmes** : Slate/Zinc (dark), Light/Clean, Matrix/Hacker (cyberpunk)
- **Glassmorphisme** : cartes blur, particules canvas, animations fluides
- **Design system** : variables CSS, composants réutilisables

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Navigateur (:8501)                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  SPA Vanilla JS — Dashboard, Scan, Reports, Chat, Config   │ │
│  └────────────────────┬───────────────────────────────────────┘ │
│                       │ REST + WebSocket                         │
│  ┌────────────────────▼───────────────────────────────────────┐ │
│  │  FastAPI (api.py)                                          │ │
│  │  /api/scan  /api/chat  /api/benchmark  /api/probes/status  │ │
│  └────┬──────────┬──────────┬──────────┬─────────────────────┘ │
│       │          │          │          │                         │
│  ┌────▼───┐ ┌───▼────┐ ┌──▼───┐ ┌───▼────────┐                 │
│  │ Nmap   │ │Nuclei  │ │CrewAI│ │ Ollama/     │                 │
│  │ +Recon │ │+SAST   │ │agents│ │ DeepSeek    │                 │
│  │        │ │+Trivy  │ │      │ │ /OpenAI/etc │                 │
│  └────────┘ └────────┘ └──────┘ └────────────┘                 │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Sondes distantes (sentient_agent.py :8502)               │   │
│  │  VPS Paris 🟢 — DMZ Berlin 🔴 — VPN NY 🟢                │   │
│  │  Heartbeat → /api/probes/heartbeat toutes les 30s         │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### 🐳 Docker (recommandé)
```bash
git clone https://github.com/magasword22/sentient-ai.git
cd sentient-ai
docker compose up --build -d
# → http://localhost:8501
```

### 🖥️ Manuel
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8501
# → http://localhost:8501
```

### 🚀 One-liner
```bash
curl -sL https://raw.githubusercontent.com/magasword22/sentient-ai/main/install.sh | bash
```

---

## ⚡ Démarrage rapide

```bash
# Lancer l'API
uvicorn api:app --host 0.0.0.0 --port 8501

# Login : admin / admin
# → Dashboard → Lancer un Audit → localhost → Mode Démo → 🚀

# Déployer une sonde distante
python3 sentient_agent.py --master http://SERVEUR_IP:8501 --name "VPS Paris"

# CI/CD
python3 sentient_cli.py --target example.com --format sarif --output results.sarif
```

---

## 🧠 Fournisseurs LLM supportés

| Provider | Modèle | Type |
|---|---|---|
| Ollama | llama3.1:8b (local) | Gratuit, GPU |
| DeepSeek | deepseek-chat | Cloud, pas cher |
| OpenAI | gpt-4o | Cloud |
| Anthropic | claude-3-5-sonnet | Cloud |
| Groq | mixtral-8x7b | Cloud, rapide |
| Mistral | mistral-large | Cloud, EU |

Configurable dans **Configuration → Connecteur IA**.

---

## 📡 Sondes distantes

```bash
# Sur le VPS
python3 sentient_agent.py --master http://SERVEUR:8501 --name "VPS Paris"

# Dans l'interface
# Configuration → Sondes → Ajouter
# Lancer un Audit → Sonde → VPS Paris
# Monitoring → 🛰️ voir l'état en temps réel
```

---

## 📂 Structure du projet

```
sentient-ai/
├── api.py              # Backend FastAPI (REST + WebSocket)
├── static/index.html   # Frontend SPA (Vanilla JS, glassmorphism)
├── sentient_agent.py   # Sonde de scan distante
├── sentient_cli.py     # CLI pour CI/CD
├── scanner.py          # Nmap, Nuclei, SAST, Trivy
├── agents.py           # CrewAI multi-agents + LLM providers
├── chat.py             # Assistant virtuel RAG
├── rag.py              # ChromaDB vector store
├── autotune.py         # Optimisation matérielle + télémétrie
├── database.py         # SQLite (scans, users, schedules)
├── compliance.py       # Cartographie conformité
├── roi_calculator.py   # Calculateur de risque financier
├── host_auditor.py     # Audit système LPE via SSH
├── report_config.py    # Configuration White-Label
├── standards/          # 4 standards de sécurité (751 lignes)
│   ├── anssi_guide.md
│   ├── cis_benchmarks.md
│   ├── owasp_top_10.md
│   └── kernel_exploits.md
├── assets/             # Logo et ressources
├── reports/            # Rapports PDF générés
├── rag_db/             # Base vectorielle ChromaDB
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 📜 Licence

Développé pour l'orchestration avancée de Red Teaming. Usage interne et éducatif.
