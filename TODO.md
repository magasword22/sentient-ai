# 📋 Feuille de Route & To-Do List : Sentient AI

Ce document présente la vision globale, la feuille de route détaillée et le suivi des évolutions de **Sentient AI** (moteur PTaaS 100% local), adaptées aux besoins des pentesters, du marketing, des présentateurs, et des DevOps.

---

## 🗺️ Vision Globale de l'Architecture Cible

Pour soutenir ces nouvelles fonctionnalités, voici le schéma de l'architecture modulaire proposée :

```mermaid
graph TD
    %% Entrées utilisateur/rôles
    subgraph Roles ["🎭 Profils Utilisateurs"]
        P[Pentester / Sécurité]
        M[Marketing / Commercial]
        Pr[Présentateur / Démo]
        D[DevOps / IT Manager]
    end

    %% Interface
    subgraph UI ["🖥️ Streamlit SaaS Dashboard"]
        Dash[Tableau de Bord & KPIs]
        Chat[Assistant Virtuel RAG]
        Conf[Config Connecteurs & RBAC]
        Edit[Éditeur de Templates Nuclei]
    end

    %% Cœur du Système
    subgraph Orchestration ["🧠 Moteur d'Orchestration Agentique (CrewAI + Ollama)"]
        Analyst[Analyst Agent]
        Writer[Pentester Report Agent]
        Defender[Defender Agent - Mitigations]
        Validator[Exploit Validator Agent]
        Translator[Translator Agent]
    end

    %% Outils & Scanners
    subgraph Pipeline ["⚙️ Pipeline de Scanners"]
        Nmap[Nmap & Vuln Scripts]
        Nuclei[Nuclei & Custom Templates]
        Recon[Outils Recon: Subfinder, Gobuster]
    end

    %% Bases et Sorties
    subgraph Data ["💾 Stockage & RAG"]
        DB[(SQLite - Historique)]
        Chroma[(ChromaDB - Référentiels Sec)]
    end

    subgraph Outputs ["📤 Livrables & Intégrations"]
        PDF[PDF White-Label / Multi-langues]
        Dojo[DefectDojo API]
        Webhook[Alertes Slack / Teams]
        CI[SARIF / JUnit para CI/CD]
    end

    %% Connexions
    P & M & Pr & D --> UI
    Dash & Chat & Edit & Conf --> Orchestration
    Orchestration --> Pipeline
    Pipeline --> Data
    Orchestration --> Data
    Orchestration --> Outputs
```

---

## 🛠️ Évolutions par Profils Utilisateurs

### 1. Pour les Pentesters & Équipes de Sécurité
Les experts en cybersécurité recherchent la flexibilité technique, la précision du scan et le contrôle total du comportement des agents IA.

| Fonctionnalité | Description | Impact Technique | Statut |
| :--- | :--- | :--- | :---: |
| **Sélections de Vulnérabilités Avancées** | Configuration dynamique des types de scans depuis le menu Audit (RCE, injections, SSL/TLS, DNS, default-logins, etc.). | Cartographie directe des tags Nuclei en cours d'exécution. | 🟢 **Implémenté** |
| **Pipeline de Reconnaissance Étendu** | Intégration d'outils DNS et de fuzzing en amont : `Subfinder`, `Amass`, et `Gobuster`/`ffuf`. | Augmente la surface d'attaque identifiée avant l'évaluation. | 📅 **Planifié** |
| **Éditeur de Templates Nuclei Intégré** | Interface web avec coloration syntaxique permettant d'écrire, modifier et tester des templates YAML. | Permet de cibler des vulnérabilités propriétaires internes. | 📅 **Planifié** |
| **Agent de Validation d'Exploits** | Agent CrewAI spécialisé ("Exploit Validator") exécutant des PoC non destructives pour valider les failles. | Réduction à 0% du taux de faux positifs. | 📅 **Planifié** |
| **Agent Défensif (Blue Team Companion)** | Agent générant des correctifs automatisés (ModSecurity WAF, configurations Nginx, règles de pare-feu, Yara). | Génère un guide de remédiation technique immédiat. | 📅 **Planifié** |
| **Techniques d'Évasion de Pare-feu** | Options Nmap : fragmentation de paquets (`-f`), leurres (`-D`), usurpation MAC. | Permet d'évaluer la résilience des pare-feux et IDS/IPS clients. | 📅 **Planifié** |

> [!TIP]
> **Sécurité locale accrue :** Toutes ces opérations de validation d'exploits s'effectuent via l'instance Ollama locale, garantissant qu'aucune donnée de faille zero-day ne fuite vers des API tierces.

---

### 2. Pour le Marketing & les Équipes Commerciales
Le marketing et les commerciaux ont besoin de livrables esthétiques, valorisants pour leur marque, et de métriques d'impact pour convaincre les décideurs.

| Fonctionnalité | Description | Impact Business | Statut |
| :--- | :--- | :--- | :---: |
| **Rapports White-Label (Marque Blanche)** | Téléversement de logo, palettes CSS de couleurs personnalisées, en-têtes et pieds de page PDF. | Permet aux cabinets et MSSP de revendre des rapports sous leur propre marque. | 🟢 **Implémenté** |
| **Calculateur de Risque Financier (ROI)** | Tableau de bord estimant l'impact financier brut (sectoriel, RGPD, NIS 2) face au coût de remédiation. | Argumentaire financier direct auprès des directions générales (C-Level). | 🟢 **Implémenté** |
| **Badges de Conformité Réglementaire** | Cartographie automatique aux frameworks : ISO 27001, SOC2, PCI-DSS et ANSSI. | Donne un aperçu instantané de la préparation à une certification. | 🟢 **Implémenté** |
| **Traduction Automatique des Rapports** | Agent de traduction pour générer les rapports en plusieurs langues (EN, FR, ES, DE). | Facilite le business international et les filiales mondiales. | 🟢 **Implémenté** |
| **Liens de Partage Sécurisés Temporaires** | URL sécurisée, chiffrée et expirante hébergeant une version interactive en lecture seule du rapport. | Évite le partage de documents sensibles par courriel non sécurisé. | 📅 **Planifié** |

---

### 3. Pour les Présentateurs, Démos & Avant-Vente
Ces fonctionnalités visent à maximiser l'effet "Wow" lors de démonstrations en direct tout en éliminant les aléas techniques du direct.

```
       🎨 Thème Cyberpunk / High-Tech
                    │
                    ▼
 🛡️  [Mode Démo Instantané (Simulation)] ──► ⚡ Zéro attente réseau (Cibles fictives)
                    │
                    ▼
       📊 Visualiseur de Pensée IA en Live
```

* **Mode Démo Instantané (Simulation)** :
  * Un bouton permettant de lancer un scan simulé ultrarapide sur une cible fictive (`target.demo`). Le système charge instantanément des résultats prédéfinis de vulnérabilités critiques (ex: Log4j, fuites de clés API) et lance l'IA pour générer le rapport en direct.
  * **Intérêt** : Évite les temps d'attente d'un scan réseau réel (qui peut prendre de 10 à 30 minutes) pendant une présentation de 5 minutes devant un client.
* **Visualiseur Graphique des Agents (Thought Stream)** :
  * Un composant visuel dynamique (graphe ou bulles de discussion animées) montrant les interactions en temps réel entre l'analyste SOC et le Lead Pentester. L'utilisateur voit l'IA "réfléchir", faire des recherches web et débattre de la sévérité d'une faille.
  * **Intérêt** : Rend l'intelligence artificielle agentique tangible et captivante pour l'audience.
* **Moniteur de Performance Matérielle (GPU Telemetry)** :
  * Affichage en temps réel de la charge CPU/GPU, VRAM et de la vitesse de génération (tokens/seconde). [🟢 **Implémenté**]
* **Personnalisation des Thèmes d'Interface (UI)** :
  * Un sélecteur de thèmes dans l'onglet configuration (Slate/Zinc, Light/Clean, Matrix/Hacker). [📅 **Planifié**]

---

### 4. Pour les Développeurs, DevOps & Administrateurs
Ce profil recherche la facilité de déploiement, l'automatisation et l'intégration dans des architectures existantes.

1. **Architecture Distribuée (Agents Distants)** :
   * Permettre à Sentient AI de déployer des conteneurs légers de scan (sondes Nmap/Nuclei uniquement) sur des serveurs distants ou des VPS, puis de renvoyer les fichiers JSON bruts au serveur central pour l'analyse IA.
   * *Bénéfice* : Permet d'auditer des réseaux internes segmentés sans y installer tout le moteur IA.
2. **Playbooks de Remédiation Automatique** : [🟢 Implémenté]
   * En plus d'expliquer comment corriger une faille, l'assistant virtuel propose des boutons pour télécharger des scripts d'automatisation de correctifs : playbooks **Ansible**, scripts **Bash**, configurations **Terraform**, ou correctifs de fichiers **Dockerfile**.
3. **Intégration CI/CD Native (DevSecOps)** :
   * Lancement en mode ligne de commande standardisé (`sentient scan --target target.com --format sarif`) pour intégrer les résultats dans les onglets de sécurité de GitHub, GitLab ou SonarQube.
4. **Planificateur de Scans Récurrents (Cron)** :
   * Planifier des audits automatiques réguliers (toutes les nuits, toutes les semaines) sur un périmètre donné. Le système envoie une alerte Slack/Discord/E-mail uniquement si de nouvelles failles d'une sévérité critique ou haute sont découvertes.
5. **Authentification & Contrôle d'Accès (RBAC)** :
   * Protection de l'interface Streamlit par une couche d'authentification (compatible LDAP, OAuth2/OIDC, ou gestion locale SQLite) avec des rôles définis (ex: *Admin* pour lancer les scans, *Client* pour uniquement consulter les rapports dans le coffre-fort).
6. **Lancement unifié Docker Compose (One-Click)** : [🟢 Implémenté]
   * Fournir un fichier `docker-compose.yml` orchestrant l'application Streamlit et une instance Ollama pré-configurée avec prise en charge du GPU pass-through (CUDA/ROCm/Vulkan).
   * *Bénéfice* : Déploiement instantané sans aucune dépendance Python ou système.
7. **TUI d'installation interactive (terminal menu)** :
   * Mettre à niveau `install.sh` avec une interface TUI interactive (ex: via `dialog`) pour choisir les options d'installation, la taille du LLM par défaut et les configurations réseaux (reverse proxy).
   * *Bénéfice* : Améliore radicalement l'expérience de l'administrateur lors de l'installation.
8. **Optimisation Matérielle Dynamique (Hardware Tuning)** :
   * Profilage automatique de la RAM, VRAM et CPU lors du premier démarrage pour configurer de manière optimale le nombre de threads d'Ollama et les limites concurrentes de scan Nuclei.
   * *Bénéfice* : Vitesse de réponse IA et de scan maximisée sans configuration manuelle.
9. **Infrastructure-as-Code (Terraform & Ansible)** :
   * Fournir des templates Terraform et playbooks Ansible pour provisionner et configurer automatiquement des serveurs d'audit cyber dédiés sur AWS, GCP, Azure ou Scaleway en 3 minutes.
   * *Bénéfice* : Automatisation du cycle de vie des serveurs d'audit (Infrastructure immutable).
10. **Chart Helm Kubernetes Enterprise** :
    * Créer un Helm Chart complet pour déployer Sentient AI sur des clusters Kubernetes d'entreprise avec gestion des volumes persistants pour l'historique et intégration des secrets.
    * *Bénéfice* : Intégration cloud native simplifiée pour les grandes architectures.

---

## 📊 Matrice d'Impact vs Effort de Développement

| Catégorie | Fonctionnalité clé | Effort estimé | Impact perçu | Priorité recommandée |
| :--- | :--- | :--- | :--- | :---: |
| **Démos / Présentateurs** | Mode Démo (Simulation instantanée) | 🟢 Faible | 🔴 Très Élevé | **Haute** |
| **Sécurité / Pentest** | Agent de validation d'exploits (PoC) | 🟡 Moyen | 🔴 Très Élevé | **Haute** |
| **Développeurs / DevOps**| Déploiement Docker Compose unifié | 🟢 Faible | 🔴 Très Élevé | **Haute** |
| **Marketing / Sales** | Rapports PDF personnalisés (White-Label) | 🟢 Faible | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| Planificateur de scans (Cron) | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Sécurité / Pentest** | Agent de mitigation défensive | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| TUI d'installation pour install.sh | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| Optimisation matérielle dynamique | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| Infrastructure-as-Code (Terraform) | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| Chart Helm Kubernetes | 🟡 Moyen | 🟡 Moyen | **Moyenne** |
| **Développeurs / DevOps**| Architecture de scan distribuée | 🔴 Élevé | 🟡 Moyen | **Basse** |

---

## 📋 Suivi Détaillé des Tâches (To-Do List)

### 1. 🧠 Modèles & Intelligence IA
- [x] **Moteur d'IA Hybride (Local + API Cloud)** : Ajouter une option dans la configuration pour basculer vers des API distantes (OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet, Groq) en cas de besoin de performances ou de rapidité.
- [ ] **RAG Étendu & Référentiels Cyber** : Vectoriser et intégrer les guides de l'ANSSI, les benchmarks CIS et les documentations de remédiation OWASP dans la base vectorielle locale (ChromaDB) pour enrichir le contexte de l'IA.

### 2. ⚡ Capacités de Scan & Sécurité
- [x] **Sélections avancées de vulnérabilités** : Formulaire à checkboxes 3 colonnes mappé sur les tags Nuclei (`rce`, `sqli`, `xss`, etc.).
- [ ] **Scans Authentifiés** : Implémenter la prise en charge d'identifiants (clés SSH, tokens d'API, cookies de session web) dans `scanner.py` pour réaliser des scans internes en profondeur.
- [ ] **Intégration SAST & Conteneurs (DevSecOps)** :
  - [ ] Intégrer `Trivy` pour l'analyse de vulnérabilités dans les images Docker et conteneurs.
  - [ ] Intégrer `Semgrep` ou `Bandit` pour le scan de vulnérabilités directement dans le code source de l'organisation.

### 3. 📅 Automatisation, Planification & Alertes
- [ ] **Planificateur d'Audits Récurrents (Cron)** : Ajouter un module de planification dans l'interface Streamlit permettant d'automatiser des scans réguliers (quotidiens, hebdomadaires, mensuels).
- [x] **Notifications & Alertes Temps Réel** : Mettre en œuvre des connecteurs webhook pour envoyer des alertes instantanées sur Slack, Microsoft Teams, Discord ou par e-mail en cas de détection d'une vulnérabilité critique.

### 4. 🛠️ Correction Assistée & Connexions DevOps
- [x] **Génération Automatisée de Scripts de Remédiation** : Permettre à l'IA d'éditer ou de proposer au téléchargement des scripts prêts à l'emploi (playbooks Ansible, configurations Terraform, correctifs de fichiers Dockerfile, règles de pare-feu).
- [ ] **Intégration d'outils de ticketing** : Ajouter des boutons dans le rapport ou l'assistant virtuel pour pousser automatiquement les vulnérabilités détectées sous forme de tickets Jira ou de GitLab/GitHub Issues.

### 5. 📊 Rapports & Conformité Business
- [x] **Rapports White-Label** : Personnalisation de logo, couleurs et nom de marque.
- [x] **Justifications Réglementaires & ROI** : Mentions DORA/NIS 2/RGPD, calculs financiers ROI et outil de simulation interactif.
- [x] **Traduction automatique** : Permettre la génération instantanée de rapports PDF en anglais, espagnol, allemand, etc. à l'aide d'agents de traduction IA.

### 6. 📦 Déploiement, DevOps & Facilité d'Installation
- [x] **Déploiement Docker Compose** : Écrire un fichier `docker-compose.yml` multi-conteneurs avec intégration automatique d'Ollama et de l'application avec accélération matérielle.
- [ ] **TUI (Text User Interface) d'installation** : Moderniser `install.sh` avec un menu terminal interactif pour guider l'utilisateur.
- [ ] **Optimisation matérielle automatique** : Profiler le système (RAM/VRAM/GPU) pour auto-configurer Ollama et les taux de threads de Nuclei.
- [ ] **Templates Terraform & Ansible (IaC)** : Développer des scripts pour instancier des instances d'audit dédiées dans le Cloud en quelques clics.
- [ ] **Chart Helm Kubernetes** : Concevoir les fichiers de configuration Kubernetes Helm pour le déploiement en entreprise.
