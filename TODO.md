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
- [ ] **Fallback automatique** : si Ollama est down → DeepSeek → OpenAI — chaîne de secours configurable
- [ ] **Chaînage multi-LLM** : modèle local rapide pour les tâches simples, cloud puissant pour l'analyse finale
- [ ] **Comparateur de fournisseurs** : benchmarker plusieurs LLM sur le même prompt (vitesse, coût, qualité)
- [ ] **Estimation de coût** : afficher le coût estimé en tokens/€ avant chaque requête cloud
- [ ] **Cache de réponses LLM** : éviter de re-générer les mêmes analyses (économie de tokens)
- [ ] **Modèles locaux additionnels** : llama.cpp, vLLM, TGI, Ollama multi-modèles
- [ ] **Fine-tuning local** : entraîner un modèle sur les rapports passés pour des recommandations personnalisées
- [ ] **Mode hors-ligne total** : tout fonctionne sans Internet (Ollama + RAG + outils locaux)
- [ ] **Prompt library** : bibliothèque de prompts par type d'audit (web, AD, cloud, conformité)

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
- [ ] **Audit Active Directory avancé** — PingCastle/PurpleKnight-like : analyse des chemins d'attaque, délégations dangereuses, comptes à risque, mauvaises configurations GPO, niveau de maturité AD
- [ ] **Cartographie des permissions AD** : arbre visuel des groupes, ACLs, AdminSDHolder, comptes Kerberoastables/ASREProastables
- [ ] **Audit Cloud IAM** : AWS, GCP, Azure — politiques, clés inactives, rôles privilégiés
- [ ] **Terraform / Ansible** : provisionnement automatique de sondes
- [ ] **Helm Chart** : déploiement Kubernetes

### 🔎 Scan de Données Sensibles
- [ ] **Scanner de fichiers** : détection de secrets dans les partages réseau et dossiers locaux — mots de passe en clair, fichiers `.env`, `id_rsa`, tokens, certificats
- [ ] **Détection de données personnelles** : RIB/IBAN, cartes bancaires, numéros de sécu, pièces d'identité numérisées, emails, adresses postales
- [ ] **Scan de partages SMB/NFS** : exploration automatisée des partages réseau accessibles, permissions faibles
- [ ] **Classification automatique** : scoring de criticité des fichiers exposés, rapport de conformité RGPD
- [ ] **Intégration au pipeline PrivEsc** : exploiter les secrets trouvés pour l'élévation de privilèges

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

---

## 🤖 Propulsable par IA (Qwen Code)

Ces items peuvent être implémentés en session maintenant — pas de dépendances externes, juste du code :

| Item | Effort |
|---|---|
| **Thèmes UI fonctionnels** — fix `applyTheme()` dans `loadConfig()` | 5 min |
| **Licence** — créer `LICENSE.md` | 5 min |
| **Explication coffre à PoC** — ajouter description dans l'UI | 5 min |
| **Badge GitHub** — `![Sentient Audit](...)` | 5 min |
| **Prompt library** — fichier JSON de prompts par type d'audit | 10 min |
| **Mode hors-ligne total** — flag pour désactiver les providers cloud | 10 min |
| **Cache de réponses LLM** — simple dict in-memory | 15 min |
| **Preview RAG** — afficher titre + extrait avant activation | 15 min |
| **One-liner sonde** — script `install_agent.sh` | 15 min |
| **Systemd natif** — `sentient.service` mis à jour | 20 min |
| **Section CI/CD dédiée** — doc + exemples GitHub Actions | 20 min |
| **Niveaux de détail PDF** — sélecteur Exécutif/Standard/Complet | 30 min |
| **Tutoriel onboarding** — overlay première connexion | 30 min |
| **Changement de modèle LLM local** — sélecteur dans l'UI | 30 min |
| **Fallback automatique LLM** — chaîne Ollama→DeepSeek→OpenAI | 30 min |
| **Streaming LLM temps réel** — SSE endpoint pour le chat | 45 min |
| **ROI métier complet** — restaurer sliders interactifs | 45 min |
| **Groupes utilisateurs + rôles custom** — DB + UI | 1 h |
| **Comparateur de fournisseurs IA** — benchmark automatique | 1 h |
| **Scanner de fichiers sensibles** — regex PII/secrets en Python | 2 h |
| **Webhooks** — tester et finaliser Slack/Discord/Teams | 2 h |

> 💡 Demande-moi simplement « Implémente X » et je le code.
