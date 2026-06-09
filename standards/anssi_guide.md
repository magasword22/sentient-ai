# Recommandations de Sécurité de l'ANSSI — Guide Complet

> Source : Agence Nationale de la Sécurité des Systèmes d'Information (France)
> Références : BP-028 (Linux), BP-042 (Active Directory), Guide d'hygiène informatique

---

## 1. Durcissement des systèmes GNU/Linux (Guide ANSSI BP-028)

### 1.1 Politique d'accès et d'authentification
- Désactiver le compte `root` pour les connexions SSH directes : `PermitRootLogin no` dans `/etc/ssh/sshd_config`
- Utiliser l'authentification par clé publique uniquement : `PasswordAuthentication no`, `PubkeyAuthentication yes`
- Appliquer des permissions strictes sur les clés privées : `chmod 600 ~/.ssh/id_*`
- Configurer PAM pour imposer des mots de passe forts : `pam_pwquality.so minlen=12 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1`
- Verrouiller les comptes après 5 tentatives échouées : `pam_tally2.so deny=5 unlock_time=1800`
- Désactiver les comptes système inutilisés : `usermod -s /sbin/nologin <compte>`

### 1.2 Cloisonnement réseau
- Mettre en œuvre un pare-feu local avec politique par défaut de rejet : `iptables -P INPUT DROP ; iptables -P FORWARD DROP`
- N'autoriser que les flux strictement nécessaires (ports applicatifs, SSH depuis IPs de management)
- Segmenter les interfaces réseau (physiques et logiques) selon le niveau de sensibilité
- Utiliser `nftables` de préférence à `iptables` pour une gestion plus granulaire
- Isoler les conteneurs et machines virtuelles avec des bridges dédiés

### 1.3 Mises à jour et correctifs
- Déployer `unattended-upgrades` pour les correctifs de sécurité critiques
- Maintenir un inventaire des versions logicielles (OS, middlewares, librairies)
- Appliquer les correctifs sous 48h pour les vulnérabilités critiques (score CVSS ≥ 9.0)
- Tester les mises à jour sur un environnement de pré-production avant déploiement

### 1.4 Journalisation et supervision
- Centraliser les logs vers un SIEM : `rsyslog` ou `journald-upload`
- Activer l'audit des appels système avec `auditd` : surveiller `/etc/passwd`, `/etc/shadow`, exécutions `sudo`
- Configurer la rotation des logs pour éviter la saturation disque : `logrotate` avec compression
- Synchroniser les horloges via NTP pour la corrélation temporelle des événements

### 1.5 Durcissement noyau (sysctl)
```bash
# Désactiver le routage IP sauf si routeur
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Protection anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorer les broadcasts ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Protection contre les attaques SYN flood
net.ipv4.tcp_syncookies = 1

# Désactiver les redirections ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Limiter les core dumps
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false

# Restreindre l'accès au buffer dmesg
kernel.dmesg_restrict = 1

# Activer ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2
```

---

## 2. Sécurisation Active Directory (Guide ANSSI BP-042)

### 2.1 Modèle d'administration à trois tiers (Tiering)
- **Tier 0** : Contrôleurs de domaine, comptes Domain Admin — ne jamais se connecter sur Tier 1 ou Tier 2
- **Tier 1** : Serveurs d'applications, serveurs de fichiers, bases de données
- **Tier 2** : Postes de travail, postes administratifs dédiés (PAW)
- Interdire les sessions interactives entre tiers via GPO et restrictions de logon

### 2.2 Protection des comptes privilégiés
- Imposer une longueur minimale de 15 caractères pour les comptes d'administration
- Activer la protection contre l'utilisation de mots de passe compromis (Azure AD Password Protection)
- Utiliser des comptes dédiés par niveau de privilège (pas de compte admin multi-usage)
- Mettre en œuvre l'authentification multifacteur (MFA) pour tous les accès administratifs
- Auditer les appartenances aux groupes : `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Administrators`

### 2.3 Sécurisation des protocoles d'authentification
- Désactiver NTLMv1 et LM hash : `Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM`
- Activer la signature SMB obligatoire : `Microsoft network server: Digitally sign communications (always) = Enabled`
- Déployer Kerberos Armoring (FAST) pour protéger les tickets Kerberos
- Changer le mot de passe du compte KRBTGT périodiquement (2 fois par an)

### 2.4 Délégation et permissions
- Limiter au strict minimum les membres des groupes `Administrateurs de l'entreprise` et `Administrateurs du domaine`
- Auditer les droits de délégation non contrainte (Unconstrained Delegation) — les éliminer si possible
- Surveiller les comptes avec `TrustedForDelegation` ou `msDS-AllowedToDelegateTo`

### 2.5 Sécurité des contrôleurs de domaine
- Isoler les DCs sur un réseau de management dédié
- Restreindre l'accès RDP et WinRM aux DCs depuis des IPs de management uniquement
- Activer Credential Guard et Device Guard sur les DCs Windows Server 2016+
- Configurer le vidage sécurisé du cache LSASS : `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`

---

## 3. Sécurisation des serveurs Web et applications

### 3.1 Durcissement Apache / Nginx
- Désactiver les signatures serveur : `ServerSignature Off` et `ServerTokens Prod`
- Désactiver les méthodes HTTP inutilisées : `TRACE`, `TRACK`, `OPTIONS`, `PUT`, `DELETE`
- Configurer les en-têtes de sécurité HTTP :
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `Content-Security-Policy: default-src 'self'; script-src 'self'`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- Limiter la taille des requêtes entrantes pour prévenir les DoS : `LimitRequestBody`, `client_max_body_size`

### 3.2 Sécurité des bases de données
- Appliquer le principe du moindre privilège aux comptes de service DB
- Chiffrer les connexions : TLS pour PostgreSQL/MySQL, TDE pour SQL Server
- Auditer les connexions et les requêtes sensibles (SELECT sur tables PII)
- Désactiver les fonctionnalités non utilisées (xp_cmdshell, LOAD DATA LOCAL INFILE)

### 3.3 Protection contre les injections
- Utiliser des requêtes paramétrées (Prepared Statements) pour toutes les requêtes SQL
- Valider et échapper toutes les entrées utilisateur côté serveur
- Déployer un WAF (Web Application Firewall) avec règles OWASP Core Rule Set
- Activer Content Security Policy avec nonce pour bloquer les XSS

---
## Références
- ANSSI BP-028 : https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-un-systeme-gnulinux/
- ANSSI BP-042 : https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-active-directory/
- ANSSI Guide d'hygiène informatique : https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/
