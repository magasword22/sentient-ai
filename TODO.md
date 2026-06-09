# 📋 Feuille de Route — Sentient AI v3

> Dernière mise à jour : 9 juin 2026

---

## ✅ Implémenté (v3.0 — Architecture FastAPI + SPA)

### 🏗️ Architecture
- ✅ **FastAPI backend** — remplace Streamlit, 30+ endpoints REST + WebSocket
- ✅ **SPA Vanilla JS** — zéro dépendance npm, glassmorphisme, particules canvas
- ✅ **Design system CSS** — variables, 3 thèmes, animations, composants réutilisables
- ✅ **Docker Compose** — Ollama ROCm + app, GPU passthrough

### 🔬 Scan & Découverte
- ✅ Nmap : Top 1000 / Fast / Full / Agressif / Scripts vuln
- ✅ Nuclei : 10+ catégories de tags configurables
- ✅ Évasion pare-feu : fragmentation, leurres, MAC spoofing
- ✅ Scans authentifiés : cookies HTTP, SSH user/pass/key
- ✅ Recon : Subfinder, Gobuster
- ✅ SAST : Semgrep + Bandit
- ✅ Trivy : conteneurs Docker / filesystem

### 🧠 IA & Analyse
- ✅ CrewAI : 5 agents (SOC Analyst, Lead Pentester, Exploit Validator, Defender, Translator)
- ✅ RAG ChromaDB avec 4 standards pré-intégrés (ANSSI, CIS, OWASP, Kernel Exploits) — activation 1 clic
- ✅ 6 fournisseurs LLM : Ollama, DeepSeek, OpenAI, Anthropic, Groq, Mistral
- ✅ Recherche Web dynamique (DuckDuckGo)
- ✅ Rapports PDF White-Label multilingues (FR, EN, ES, DE)
- ✅ Assistant virtuel (Chat RAG)
- ✅ Benchmark IA : test de vitesse tokens/sec

### 🖥️ Audits Système
- ✅ PrivEsc Multi-OS : Linux, macOS, Windows via SSH
- ✅ Coffre à PoC : génération par CVE
- ✅ Analyse ROI financier (DORA/NIS 2/RGPD)
- ✅ Planificateur de scans récurrents (cron)

### 🛰️ Architecture Distribuée
- ✅ Sondes légères (`sentient_agent.py`) avec heartbeat
- ✅ Monitoring temps réel : statut, scan actif, online/offline
- ✅ Gestion des sondes dans l'interface
- ✅ Authentification par token Bearer
- ✅ Logs live streamés via WebSocket pendant le scan

### 🔒 Sécurité
- ✅ RBAC : admin/client avec gestion des utilisateurs
- ✅ Secrets protégés : `.gitignore` pour `report_config.json`, `audits.db`
- ✅ Pare-feu : règles UFW pour SSH + app

### 🎨 Interface
- ✅ 3 thèmes : Slate/Zinc, Light/Clean, Matrix/Hacker
- ✅ Glassmorphisme, particules canvas, animations
- ✅ Barre de progression avec illusion de vitesse (shimmer, glow, fake-easing)
- ✅ Logs temps réel dans la barre de progression (subprocess output)
- ✅ Raccourcis clavier (Ctrl+Enter)
- ✅ Affichage IP LAN pour accès réseau

---

## 🔮 Roadmap future (v3.1+)

### Exploitation & Validation
- [ ] **Bac à sable d'exploitation** : conteneur Docker éphémère pour tester les PoC sans risque
- [ ] **Exploit Validator automatique** : exécution de PoC non destructives
- [ ] **Intégration Metasploit** : lancement de modules MSF depuis l'interface

### Cloud & Infrastructure
- [ ] **Cartographie Active Directory** : BloodHound-like, chemins d'attaque AD
- [ ] **Audit Cloud IAM** : AWS, GCP, Azure — politiques, clés inactives
- [ ] **Terraform / Ansible** : provisionnement automatique de sondes
- [ ] **Helm Chart Kubernetes** : déploiement enterprise

### Threat Intelligence
- [ ] **Intégration CISA KEV** : catalogue des vulnérabilités activement exploitées
- [ ] **Flux CVE en temps réel** : ingestion automatique dans ChromaDB
- [ ] **Abonnement alertes** : notification sur nouvelles CVE critiques

### Interface
- [ ] **Dark mode OLED** : thème noir pur (#000)
- [ ] **Tableau de bord personnalisable** : widgets drag & drop
- [ ] **Mode kiosque** : plein écran pour écrans de monitoring
- [ ] **PWA** : installation comme application desktop/mobile

### Performance
- [ ] **Scan parallèle multi-sondes** : répartition de charge
- [ ] **Cache de scan** : éviter de re-scanner les mêmes cibles
- [ ] **Streaming LLM** : tokens en temps réel dans le chat

---

## 📊 État global

| Catégorie | Complétion |
|---|---|
| Architecture | 100% ✅ |
| Scan & Découverte | 100% ✅ |
| IA & Analyse | 100% ✅ |
| Interface | 100% ✅ |
| Sondes & Monitoring | 100% ✅ |
| Sécurité | 100% ✅ |
| CI/CD | 100% ✅ |
| Cloud & Enterprise | 0% |
| Threat Intel | 0% |
| **Total** | **~85%** |
