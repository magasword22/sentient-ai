# 📋 Feuille de Route — Sentient AI v3

> Dernière mise à jour : 9 juin 2026

---

## ✅ Implémenté (v3.0 — Architecture FastAPI + SPA)

### 🏗️ Architecture
- ✅ FastAPI backend — 30+ endpoints REST + WebSocket
- ✅ SPA Vanilla JS — zéro dépendance npm, glassmorphisme, particules canvas
- ✅ Design system CSS — variables, 3 thèmes, animations, composants réutilisables
- ✅ Docker Compose — Ollama ROCm + app, GPU passthrough

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
- ✅ RAG ChromaDB + 4 standards pré-intégrés (ANSSI, CIS, OWASP, Kernel Exploits)
- ✅ 6 fournisseurs LLM : Ollama, DeepSeek, OpenAI, Anthropic, Groq, Mistral
- ✅ Recherche Web dynamique (DuckDuckGo)
- ✅ Rapports PDF White-Label multilingues
- ✅ Assistant virtuel RAG
- ✅ Benchmark IA : test de vitesse tokens/sec

### 🖥️ Audits Système
- ✅ PrivEsc Multi-OS : Linux, macOS, Windows via SSH
- ✅ Coffre à PoC : génération par CVE
- ✅ Analyse ROI financier (DORA/NIS 2/RGPD)
- ✅ Planificateur de scans récurrents

### 🛰️ Architecture Distribuée
- ✅ Sondes légères avec heartbeat
- ✅ Monitoring temps réel des agents
- ✅ Gestion des sondes dans l'interface
- ✅ Authentification par token Bearer
- ✅ Logs live des subprocess en streaming

### 🔒 Sécurité
- ✅ RBAC : admin/client
- ✅ Secrets : stockage local, aucune donnée ne quitte la machine
- ✅ Pare-feu UFW

### 🎨 Interface
- ✅ Glassmorphisme, particules canvas, animations
- ✅ Barre de progression avec illusion de vitesse
- ✅ Logs temps réel dans la barre de scan
- ✅ Raccourcis clavier (Ctrl+Enter)
- ✅ Affichage IP LAN

---

## 🔧 Correctifs prioritaires (v3.0.1)

- [ ] **Thèmes UI fonctionnels** — le sélecteur de thème (Slate/Light/Matrix) sauvegarde la valeur mais ne l'applique pas au DOM. Ajouter `applyTheme()` dans `loadConfig()`.
- [ ] **Webhooks** — tester et valider les envois Slack/Discord/Teams depuis l'API
- [ ] **ROI métier complet** — restaurer les sliders interactifs de coûts personnalisés (comme dans l'ancien Streamlit)
- [ ] **Changer de modèle LLM local** — permettre de sélectionner un autre modèle Ollama installé sans passer par la config manuelle
- [ ] **Niveaux de détail PDF** — ajouter un sélecteur : Complet / Résumé / Exécutif dans la génération de rapport
- [ ] **Explication Coffre à PoC** — ajouter une description claire : « Génère un script inoffensif de vérification pour une CVE donnée, utilisable comme preuve lors d'un audit »
- [ ] **Sécurité & vie privée** — audit complet : vérifier qu'aucune IP, hostname, username ou clé n'est loggué dans les rapports ou les logs
- [ ] **Licence d'utilisation** — créer `LICENSE.md` avec les vrais termes (usage interne/éducatif, pas de revente sans autorisation)

---

## 🔮 Roadmap v3.1

### 🚀 Déploiement & Expérience
- [ ] **One-liner sonde** : `curl -sL .../install_agent.sh | bash` pour déployer une sonde en 1 commande
- [ ] **Systemd natif** : `sentient start/stop/status` démarre l'API comme les autres services
- [ ] **Tutoriel onboarding** : overlay discret au premier lancement, non-bloquant, SKIP possible
- [ ] **Certificats SSL** : accepter/configurer un certificat Let's Encrypt ou custom dans l'interface

### 👥 Utilisateurs & Permissions
- [ ] **Groupes d'utilisateurs** : créer des rôles préconfigurés (Lecteur, Auditeur, Admin, SuperAdmin)
- [ ] **Permissions granulaires** : restreindre l'accès à certaines pages/fonctions par rôle
- [ ] **Rôles custom** : créer un rôle personnalisé avec sélection fine des permissions

### 📊 Visualisation
- [ ] **Graphe BloodHound-like** : visualisation des chemins d'élévation de privilèges (utilisateurs → groupes → permissions)
- [ ] **Cartographie réseau** : graphique interactif des hôtes découverts et services exposés

### 🧠 IA & RAG
- [ ] **Preview RAG** : voir le contenu des standards avant activation (titre, extrait, nombre de chunks)
- [ ] **Fournisseurs IA supplémentaires** : Google Gemini, Cohere, Together AI, Replicate, Fireworks, Perplexity
- [ ] **Streaming LLM temps réel** : afficher les tokens du chat au fur et à mesure

### 📄 Rapports
- [ ] **Niveaux de détail configurables** : Exécutif (1 page) / Standard / Complet (toutes les preuves)
- [ ] **Template PDF personnalisable** : upload d'un template HTML/CSS pour les rapports
- [ ] **Export Confluence/Jira** : publier directement le rapport dans l'outil de ticketing

### 🌐 Site Web & Visibilité
- [ ] **Site vitrine** : landing page ultra-moderne présentant l'outil (design cyberpunk, animations, démo vidéo)
- [ ] **Documentation intégrée** : la doc Markdown rendue sur le site avec recherche et navigation
- [ ] **Section CI/CD dédiée** : exemples GitLab CI, GitHub Actions, Jenkins pour `sentient_cli.py`
- [ ] **Badge GitHub** : `![Sentient Audit](https://img.shields.io/...)` pour les repos scannés

### 🔬 Exploitation & Validation
- [ ] **Bac à sable d'exploitation** : conteneur Docker éphémère pour tester les PoC sans risque
- [ ] **Exploit Validator automatique** : exécution de PoC non destructives
- [ ] **Intégration Metasploit** : lancement de modules MSF depuis l'interface

### ☁️ Cloud & Enterprise
- [ ] **Cartographie AD** : BloodHound-like, chemins d'attaque Active Directory
- [ ] **Audit Cloud IAM** : AWS, GCP, Azure — politiques, clés inactives
- [ ] **Terraform / Ansible** : provisionnement automatique de sondes
- [ ] **Helm Chart** : déploiement Kubernetes

### 🕵️ Threat Intelligence
- [ ] **Intégration CISA KEV** : catalogue des vulnérabilités activement exploitées
- [ ] **Flux CVE temps réel** : ingestion automatique dans ChromaDB
- [ ] **Abonnement alertes** : notification sur nouvelles CVE critiques (email, webhook)

---

### 🎨 Interface & Design
- [ ] **Refonte graphique avancée** : améliorer le polish visuel, transitions de page, micro-interactions
- [ ] **Mode scan immersif** : vue plein écran sans chrome pendant l'audit
- [ ] **Dashboard builder** : choisir les widgets/KPIs affichés
- [ ] **Dark mode OLED** : thème noir pur (#000) pour écrans AMOLED
- [ ] **PWA** : installation comme application desktop/mobile

### 🔌 API Plugins & Extensibilité
- [ ] **Système de plugins** : API publique documentée pour extensions tierces
- [ ] **Hooks post-scan** : exécuter des scripts personnalisés après chaque audit
- [ ] **API GraphQL** : alternative REST pour requêtes flexibles
- [ ] **Webhook sortants** : envoyer résultats vers n'importe quel endpoint
- [ ] **Intégrations** : Jira, Confluence, ServiceNow, TheHive, Splunk
- [ ] **Marketplace plugins** : dépôt communautaire

## 📊 État global

| Catégorie | Complétion |
|---|---|
| Architecture | 100% ✅ |
| Scan & Découverte | 100% ✅ |
| IA & Analyse | 95% ✅ |
| Interface | 90% ✅ |
| Sondes & Monitoring | 100% ✅ |
| Sécurité | 90% ✅ |
| CI/CD | 80% ✅ |
| Expérience utilisateur | 60% |
| Interface & Design | 10% |
| API Plugins | 0% |
| Cloud & Enterprise | 0% |
| Threat Intel | 0% |
| Site & Visibilité | 0% |
| **Total** | **~75%** |
