# 📋 Feuille de Route & To-Do List : Sentient AI

Ce document répertorie les fonctionnalités implémentées ainsi que la feuille de route (backlog) des évolutions futures planifiées pour **Sentient AI** (PTaaS 100% locale).

---

## 🟢 Fonctionnalités Implémentées (Terminé)

### 1. 📊 Justification de la Conformité & Analyse ROI Cyber
- **Conformité NIS 2, DORA & RGPD** : Intégration de justifications réglementaires détaillées basées sur les niveaux de sévérité des failles détectées pour aider à l'évaluation des risques et à la conformité.
- **Formules de Coûts d'Exposition** : Justifications explicites des coûts estimés en cas de brèche de données (coûts légaux, amendes, perte de réputation, impact opérationnel) basés sur des multiplicateurs de secteur d'activité, taille d'entreprise et sensibilité des données.
- **Économies Potentielles & ROI** : Intégration de calculs clairs démontrant le retour sur investissement (ROI) des actions correctives proposées (coût de remédiation ingénierie face au coût de l'impact financier évité).
- **Ajustement Dynamique des Coûts** : Possibilité de personnaliser les coûts de base d'exposition et de remédiation par niveau de sévérité directement dans le profil de l'organisation depuis l'onglet configuration.
- **Mentions et Infobulles** : Ajout d'infobulles mathématiques et explicatives détaillant la formule de calcul appliquée aux valeurs financières.

### 2. ⚡ Capacités d'Audit Multicritères & Configuration UI
- **Sélection des Cibles de Scan** : Structuration de l'interface en 3 colonnes permettant d'activer/désactiver sélectivement les catégories et signatures de vulnérabilités pour Nmap et Nuclei :
  - *Failles critiques (RCE, injections de code, etc.)*
  - *Défauts d'authentification et mots de passe par défaut*
  - *Fuites d'informations et expositions de données sensibles*
  - *Mauvaises configurations de serveurs*
  - *Vulnérabilités de protocoles SSL/TLS & DNS*
  - *Services réseaux et protocoles obsolètes*
- **Mappage Dynamique** : Liaison des options de l'UI Streamlit aux tags de signatures Nuclei (`rce`, `sqli`, `xss`, `default-login`, `exposure`, `misconfig`, `ssl`, `dns`, `network`) passés au moteur de scan en temps réel.

### 3. 🎨 Personnalisation White-Label (Marque Blanche)
- **Identité Visuelle des Rapports PDF** : Personnalisation complète des rapports PDF générés depuis l'interface d'administration :
  - *Téléchargement du logo d'entreprise d'audit*
  - *Palette de couleurs primaires personnalisable via un sélecteur de couleur (color picker)*
  - *Nom d'entreprise et texte de pied de page personnalisés dans toutes les pages du PDF*

### 4. 🖥️ Diagnostic Hardware & Télémétrie GPU
- **Moniteur Temps Réel** : Ajout d'un panneau dynamique de télémétrie dans la barre latérale pour surveiller en temps réel l'utilisation de la VRAM (Ollama), le modèle de carte graphique (GPU) détecté, le modèle de langage actif et l'état de connexion du démon Ollama local.

---

## 📅 Backlog & Évolutions Futures (Planifié)

### 1. 🧠 Modèles & Intelligence IA
- [ ] **Moteur d'IA Hybride (Local + API Cloud)** : Ajouter une option dans la configuration pour basculer vers des API distantes (OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet, Groq) en cas de besoin de performances accrues ou sur des machines dépourvues de GPU dédié.
- [ ] **RAG Étendu & Référentiels Cyber** : Ingestion automatique et vectorisation des guides officiels de l'ANSSI, des benchmarks de sécurité CIS et des fiches de remédiation OWASP dans la base vectorielle locale (ChromaDB) pour enrichir la précision des conseils générés par l'IA.

### 2. ⚡ Capacités de Scan & Sécurité
- [ ] **Scans Authentifiés** : Implémenter la prise en charge de credentials (clés SSH, tokens d'API, cookies de session web) dans le module `scanner.py` pour permettre des scans internes authentifiés de haute précision.
- [ ] **Intégration DevSecOps (SAST & Conteneurs)** :
  - [ ] Intégrer le scanner `Trivy` pour l'analyse de vulnérabilités dans les images Docker et les configurations Kubernetes.
  - [ ] Intégrer `Semgrep` ou `Bandit` pour analyser le code source de l'organisation directement lors de pipelines CI/CD.

### 3. 📅 Automatisation, Planification & Alertes
- [ ] **Planificateur d'Audits Récurrents (Cron)** : Ajouter un module de planification de scans réguliers (quotidiens, hebdomadaires, mensuels) à partir de l'interface Streamlit.
- [ ] **Notifications & Alertes Temps Réel** : Mettre en œuvre des webhooks de notification vers Slack, Microsoft Teams, Discord ou par e-mail en cas de détection d'une nouvelle faille critique ou haute.

### 4. 🛠️ Correction Assistée & Connexions DevOps
- [ ] **Génération Automatique de Scripts de Remédiation** : Permettre à l'IA d'éditer ou de générer directement en téléchargement des playbooks Ansible, des correctifs de fichiers Dockerfile, ou des règles de pare-feu prêtes à l'emploi.
- [ ] **Intégration d'Outils de Ticketing** : Ajouter des connecteurs natifs pour pousser en un clic les vulnérabilités validées sous forme de tickets Jira, GitLab Issues ou GitHub Issues.

### 5. 🌍 Traduction & Internationalisation
- [ ] **Traduction Automatique des Livrables** : Permettre la génération automatique des rapports d'audit en plusieurs langues (anglais, espagnol, allemand) via des agents CrewAI de traduction dédiés.
