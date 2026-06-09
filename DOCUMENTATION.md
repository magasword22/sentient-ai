# 📖 Documentation de Référence — Sentient AI v3

> Architecture FastAPI + SPA Vanilla JS — Juin 2026

---

## 🗺️ Table des Matières
1. [Architecture](#1-architecture)
2. [Installation & Déploiement](#2-installation--déploiement)
3. [Interface Web](#3-interface-web)
4. [API Reference](#4-api-reference)
5. [Scans Réseau & Web](#5-scans-réseau--web)
6. [Audits Système (PrivEsc)](#6-audits-système-privesc)
7. [IA & LLM](#7-ia--llm)
8. [Base RAG](#8-base-rag)
9. [Sondes Distantes & Monitoring](#9-sondes-distantes--monitoring)
10. [CI/CD & CLI](#10-cicd--cli)
11. [Configuration & White-Label](#11-configuration--white-label)
12. [Sécurité](#12-sécurité)
13. [FAQ & Troubleshooting](#13-faq--troubleshooting)

---

## 1. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Navigateur → SPA Vanilla JS (static/index.html)         │
│  Glassmorphism • Particules canvas • 3 thèmes            │
└────────────────────┬─────────────────────────────────────┘
                     │ REST + WebSocket
┌────────────────────▼─────────────────────────────────────┐
│  FastAPI (api.py) — 30+ endpoints                        │
│  /api/scan  /api/chat  /api/benchmark  /api/probes/...   │
└──┬──────────┬──────────┬──────────┬──────────────────────┘
   │          │          │          │
┌──▼────┐ ┌──▼─────┐ ┌─▼──────┐ ┌─▼───────────┐
│ Nmap  │ │Nuclei  │ │CrewAI  │ │Ollama/API    │
│+Recon │ │+SAST   │ │5 agents│ │DeepSeek/...  │
│       │ │+Trivy  │ │        │ │              │
└───────┘ └────────┘ └────────┘ └──────────────┘

┌──────────────────────────────────────────────────────────┐
│  Sondes distantes (sentient_agent.py :8502)              │
│  Heartbeat → /api/probes/heartbeat toutes les 30s        │
└──────────────────────────────────────────────────────────┘
```

### Composants
| Fichier | Rôle |
|---|---|
| `api.py` | Backend FastAPI — REST + WebSocket |
| `static/index.html` | Frontend SPA — Vanilla JS, CSS embarqué |
| `sentient_agent.py` | Sonde de scan distante légère |
| `sentient_cli.py` | CLI pour intégration CI/CD |
| `scanner.py` | Orchestration Nmap, Nuclei, SAST, Trivy |
| `agents.py` | CrewAI multi-agents + LLM providers |
| `rag.py` | ChromaDB — ingestion et requêtes vectorielles |
| `database.py` | SQLite — scans, users, schedules |
| `autotune.py` | Optimisation matérielle + télémétrie système |

---

## 2. Installation & Déploiement

### Docker (recommandé)
```bash
git clone https://github.com/magasword22/sentient-ai.git
cd sentient-ai
docker compose up --build -d
# → http://localhost:8501 (interface)
# → http://localhost:11434 (Ollama)
```

### Manuel (développement)
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8501
```

### One-liner
```bash
curl -sL https://raw.githubusercontent.com/magasword22/sentient-ai/main/install.sh | bash
```

### Accès réseau
L'interface est accessible depuis n'importe quel appareil du LAN :
```
http://SERVEUR_IP:8501
```
L'IP s'affiche dans la sidebar (cliquable pour copier).

---

## 3. Interface Web

### Pages
| Page | Description |
|---|---|
| 📊 Dashboard | KPIs, historique des scans, graphiques |
| ⚡ Lancer un Audit | Formulaire complet de scan |
| 🖥️ Audit PrivEsc | Connexion SSH pour audit système |
| 🧪 Coffre à PoC | Génération de scripts de détection par CVE |
| 💰 Analyse ROI | Calculateur de risque financier |
| 📅 Planificateur | Scans récurrents automatisés |
| 📂 Rapports | Liste et téléchargement des PDF |
| 💬 Assistant IA | Chat RAG avec contexte des audits |
| 🧠 Base RAG | Upload et activation de documents |
| 📡 Diagnostic | CPU, RAM, GPU, Ollama, benchmark IA |
| 🛰️ Monitoring | État des sondes distantes |
| ⚙️ Configuration | White-label, LLM, webhook, users, sondes |

### Thèmes
- **Slate/Zinc** (défaut) : sombre professionnel
- **Light/Clean** : clair épuré
- **Matrix/Hacker** : cyberpunk, scanlines CRT

### Raccourcis clavier
- `Ctrl+Enter` : lancer le scan

---

## 4. API Reference

### Authentification
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login` | `{"username":"admin","password":"admin"}` |

### Scans
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/scan` | Lancer un scan (voir ScanRequest) |
| GET | `/api/scan/{id}` | Statut d'un scan |
| WS | `/ws/scan/{id}` | Progression live + logs |

### IA
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/chat` | Assistant virtuel RAG |
| POST | `/api/benchmark` | Test de vitesse tokens/sec |
| POST | `/api/poc` | Génération PoC par CVE |

### RAG
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/rag/upload` | Upload document |
| GET | `/api/rag/documents` | Liste documents |
| POST | `/api/rag/activate` | Activer les 4 standards |

### Sondes
| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/probes` | Ajouter une sonde |
| DELETE | `/api/probes/{name}` | Supprimer |
| POST | `/api/probes/heartbeat` | Heartbeat (appelé par l'agent) |
| GET | `/api/probes/status` | État de toutes les sondes |

### Autres
| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/history` | Historique des scans |
| GET/POST | `/api/config` | Configuration |
| GET/POST/DELETE | `/api/users` | Gestion utilisateurs |
| GET/POST/DELETE | `/api/schedules` | Planifications |
| GET | `/api/reports` | Liste rapports PDF |
| GET | `/api/reports/{file}` | Télécharger rapport |
| GET | `/api/telemetry` | Métriques système |
| GET | `/api/roi` | Calculateur ROI |
| GET | `/api/ip` | IP locale |
| POST | `/api/privesc` | Audit PrivEsc SSH |

---

## 5. Scans Réseau & Web

### Paramètres de scan (ScanRequest)
```json
{
  "target": "192.168.1.0/24",
  "nmap_mode": "T4",
  "nuclei_mode": "full",
  "nuclei_tags": ["cve", "rce", "sqli"],
  "demo_mode": false,
  "probe_url": "",
  "use_agressive": false,
  "use_vuln_script": false,
  "use_sast": false,
  "use_trivy": false,
  "evasion_fragment": false,
  "evasion_decoy": "",
  "evasion_mac": "",
  "auth_cookies": "",
  "use_subfinder": false,
  "use_gobuster": false,
  "report_lang": "Français"
}
```

### Tags Nuclei disponibles
`cve`, `default-login`, `exposure`, `misconfig`, `injections`, `rce`, `redirect`, `ssl`, `dns`, `network`

### Modes Nmap
- `T4` — Top 1000 ports (recommandé)
- `Fast` — Top 100 ports
- `Full` — 65535 ports

---

## 6. Audits Système (PrivEsc)

### Connexion SSH
```json
{
  "host": "CIBLE_IP",
  "port": 22,
  "username": "root",
  "password": "",
  "key_path": "/home/user/.ssh/id_rsa"
}
```

### Éléments audités
| OS | Éléments |
|---|---|
| Linux | SUID/SGID, capabilities, sudo, kernel, cron, Docker socket |
| macOS | SIP, TCC, sudo, Homebrew, configs sensibles |
| Windows | Registre, services, hotfixes, Autologon, PowerShell history |

---

## 7. IA & LLM

### Fournisseurs supportés
| Provider | Modèle par défaut | API Base |
|---|---|---|
| Ollama | llama3.1:8b | localhost:11434 |
| DeepSeek | deepseek-chat | api.deepseek.com/v1 |
| OpenAI | gpt-4o | api.openai.com/v1 |
| Anthropic | claude-3-5-sonnet | api.anthropic.com |
| Groq | mixtral-8x7b | api.groq.com |
| Mistral | mistral-large | api.mistral.ai/v1 |

### Configuration
Dans **Configuration → Connecteur IA** :
1. Sélectionner le fournisseur
2. Saisir le modèle
3. Saisir la clé API

Le switch est automatique : tous les scans et rapports utilisent le LLM configuré.

### Benchmark IA
Depuis **Diagnostic → Benchmark**, mesurer la vitesse :
- ≥ 25 tok/s : 🚀 Exceptionnel
- 10-25 tok/s : ⚡ Correct
- < 10 tok/s : ⚠️ Lent

---

## 8. Base RAG

### Standards pré-intégrés (désactivés par défaut)
| Standard | Contenu |
|---|---|
| 🇫🇷 ANSSI | BP-028 Linux, BP-042 AD, guide hygiène |
| 🏛️ CIS Benchmarks v8 | SSH, sysctl, filesystem, auditd |
| 🕸️ OWASP Top 10:2021 | 10 vulnérabilités + remédiation |
| 🧠 Kernel Exploits | CVE récentes, GTFOBins, Docker escape |

### Activation
1. Aller dans **🧠 Base RAG**
2. Cliquer **Activer les standards**
3. L'IA peut maintenant référencer ces documents dans ses réponses

---

## 9. Sondes Distantes & Monitoring

### Déploiement d'une sonde
```bash
python3 sentient_agent.py \
  --master http://SERVEUR_IP:8501 \
  --name "VPS Paris" \
  --port 8502 \
  --token CHANGE_ME
```

### Variables d'environnement
- `MASTER_URL` — URL du serveur principal
- `AGENT_NAME` — nom de la sonde
- `AGENT_PORT` — port d'écoute (défaut 8502)
- `AGENT_TOKEN` — token d'authentification

### Heartbeat
La sonde envoie un heartbeat au serveur toutes les 30 secondes. Si aucun heartbeat pendant 2 minutes → marquée 🔴 Offline.

### Monitoring
Page **🛰️ Monitoring** :
- 🟢 Online / 🔴 Offline
- Scan actif avec cible
- URL de la sonde

---

## 10. CI/CD & CLI

### `sentient_cli.py`
```bash
# Scan réseau → Markdown
python3 sentient_cli.py --target example.com --output rapport.md

# SAST → SARIF (GitHub Security)
python3 sentient_cli.py --target ./src --sast --format sarif --output results.sarif

# Trivy → JSON
python3 sentient_cli.py --target nginx:alpine --trivy --format json --output trivy.json

# Évasion pare-feu
python3 sentient_cli.py --target example.com --evasion --format markdown
```

---

## 11. Configuration & White-Label

### Marque blanche
Dans **Configuration** :
- Logo personnalisé (upload)
- Nom d'entreprise
- Texte pied de page
- Couleur principale
- Thème UI

### Organisation
- Secteur d'activité (Finance, Santé, E-commerce, etc.)
- Taille d'entreprise (Startup → Grande Entreprise)
- Sensibilité des données (Publique → Médicale)

### Connecteurs
- **LLM** : fournisseur, modèle, clés API
- **Webhook** : Slack, Discord, Teams, Generic
- **Sondes** : ajout/suppression de sondes distantes
- **Utilisateurs** : création/suppression (admin uniquement)

---

## 12. Sécurité

### Secrets
- Les clés API et mots de passe sont chiffrés localement et ne quittent jamais la machine
- Les données d'audit sont stockées en local uniquement
- Aucune télémétrie ou donnée n'est envoyée à des tiers
- Les clés API ne sont jamais loggées ni exposées dans les rapports

### Réseau
- Port 8501 : interface web (ouvert par défaut)
- Port 8502 : sonde distante (à ouvrir manuellement si distant)
- Port 11434 : Ollama (localhost uniquement)
- Port 22 : SSH (pour audit PrivEsc)

### Authentification
- Session locale SQLite
- Rôles : admin (full), client (lecture)
- Mots de passe hashés

---

## 13. FAQ & Troubleshooting

### Q : Ollama consomme 100% CPU
> Assurez-vous que l'accélération GPU est activée. Vérifier avec `ollama list` et `rocm-smi`.

### Q : Le scan distant échoue
> Vérifier que `sentient_agent.py` tourne sur la machine distante et que le port 8502 est ouvert. Vérifier le token.

### Q : Comment changer de LLM ?
> Configuration → Connecteur IA → sélectionner le fournisseur → sauvegarder. Tous les scans suivants utiliseront le nouveau LLM.

### Q : Où sont stockés les rapports ?
> Dans le dossier `reports/`. Accessibles via l'interface (📂 Rapports) ou directement sur le disque.

### Q : Comment déployer plusieurs sondes ?
> Lancer `sentient_agent.py` sur chaque VPS avec des noms différents. Les ajouter dans Configuration → Sondes. Le monitoring affichera toutes les sondes.

### Q : Les standards RAG sont-ils chargés automatiquement ?
> Non. Ils sont présents dans `standards/` mais doivent être activés manuellement dans l'interface (🧠 Base RAG → Activer). Ceci pour éviter de consommer de la RAM inutilement.
