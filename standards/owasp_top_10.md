# OWASP Top 10:2021 — Guide de Détection, Exploitation et Remédiation

> Source : OWASP Top 10 2021
> https://owasp.org/www-project-top-ten/

---

## A01:2021 — Broken Access Control (Contrôle d'accès défaillant)

### Description
Défaut de restriction sur ce qu'un utilisateur authentifié est autorisé à faire. Les attaquants exploitent ces failles pour accéder à des fonctionnalités/données non autorisées.

### Indicateurs de détection
- Navigation directe vers des URLs admin sans authentification (`/admin`, `/phpmyadmin`, `/api/users`)
- Modification de paramètres d'URL : `?user_id=123` → `?user_id=124` (accès aux données d'un autre utilisateur)
- Élévation de privilèges en modifiant le rôle dans le JWT ou le cookie de session
- Contournement d'authentification par force brute sur des endpoints API sans rate limiting
- Accès direct à des fichiers sensibles : `/etc/passwd`, `.env`, `.git/config`

### Remédiation
- Implémenter un middleware d'autorisation centralisé côté serveur (pas côté client)
- Utiliser des tokens JWT signés avec expiration courte et rotation de clés
- Appliquer le principe du moindre privilège (RBAC/ABAC)
- Logger et alerter sur les tentatives d'accès non autorisées (code 403)
- Désactiver le listing de répertoires sur les serveurs web
- Valider les permissions pour chaque requête, pas seulement à l'affichage du menu

---

## A02:2021 — Cryptographic Failures (Défaillances cryptographiques)

### Description
Anciennement "Sensitive Data Exposure". Données sensibles transmises ou stockées sans protection cryptographique adéquate.

### Indicateurs de détection
- Transmission de données en clair (HTTP au lieu de HTTPS)
- Algorithmes de chiffrement obsolètes : MD5, SHA1, RC4, DES, 3DES
- Certificats SSL/TLS auto-signés, expirés ou avec des chaînes de confiance incomplètes
- Stockage de mots de passe en clair ou avec un hachage faible (MD5, SHA1 sans sel)
- Absence de HSTS (HTTP Strict Transport Security)
- Cookies sans attributs `Secure`, `HttpOnly` ou `SameSite`
- Exposition de clés API, tokens ou secrets dans le code source ou les dépôts Git

### Remédiation
- Imposer HTTPS avec redirection 301 et HSTS (max-age=31536000; includeSubDomains; preload)
- Utiliser des algorithmes modernes : AES-256-GCM pour le chiffrement, Argon2id pour les mots de passe
- Générer des sels uniques par mot de passe (minimum 32 bits)
- Activer TLS 1.3, désactiver TLS 1.0/1.1, SSLv2/SSLv3
- Utiliser des certificats d'une autorité de certification reconnue

---

## A03:2021 — Injection (SQL, Command, XSS)

### Indicateurs de détection — SQLi
- Caractères `'` ou `"` dans les champs input déclenchent des erreurs SQL
- Réponses HTTP anormales : `500 Internal Server Error` après injection de guillemets
- Contournement d'auth : `' OR 1=1 --`
- Délais anormaux avec `SLEEP(5)` (Time-based blind SQLi)
- Extraction via `UNION SELECT` et `LOAD_FILE('/etc/passwd')`

### Indicateurs — Command Injection
- Concaténation : `;`, `|`, `||`, `&&`, `` ` ``
- Exécution : `$(cmd)`, `id`, `whoami`, `cat /etc/passwd`

### Remédiation
- Requêtes paramétrées (Prepared Statements) TOUJOURS
- Ne jamais passer d'entrée utilisateur à `system()`, `exec()`, `popen()`
- Validation stricte : listes blanches, expressions régulières
- WAF avec règles OWASP Core Rule Set

---

## A04:2021 — Insecure Design

### Description
Absence de modélisation des menaces, de design patterns sécurisés.

### Indicateurs
- Absence de rate-limiting sur endpoints sensibles
- Identifiants prévisibles ou séquentiels (IDOR)
- Tokens de réinitialisation prévisibles ou sans expiration
- Logique métier contournable (prix négatifs, saut d'étapes)

### Remédiation
- Modélisation des menaces (STRIDE) pendant la conception
- Tests de sécurité intégrés CI/CD (SAST + DAST)
- Rate limiting sur routes sensibles
- Tokens aléatoires (CSPRNG) avec expiration courte

---

## A05:2021 — Security Misconfiguration

### Description
Configuration par défaut non modifiée, pages d'erreur verbeuses, fonctionnalités inutiles.

### Indicateurs
- Stack traces ou versions logicielles exposées
- Interfaces admin accessibles sans auth
- Méthodes HTTP dangereuses activées (PUT, DELETE, TRACE)
- Headers de sécurité manquants : CSP, HSTS, X-Frame-Options
- Comptes par défaut (admin/admin, root/root)
- Services de debug : `/actuator`, `/debug`, `phpinfo()`

### Remédiation
- Supprimer les comptes/pages/fonctionnalités par défaut
- Configurer les en-têtes de sécurité HTTP obligatoires
- Infrastructure-as-Code pour des déploiements reproductibles
- Segmenter les environnements (dev ≠ staging ≠ prod)

---

## A06:2021 — Vulnerable and Outdated Components

### Indicateurs
- Frameworks vulnérables connus : Struts 2.x, Log4j < 2.17.1, Spring4Shell
- Librairies JS non maintenues
- Serveurs web obsolètes : Apache < 2.4.49, nginx < 1.20
- Absence de SBOM (Software Bill of Materials)

### Remédiation
- Scanner régulièrement : `npm audit`, `pip-audit`, `trivy`, `snyk`
- Automatiser les mises à jour : Dependabot, Renovate
- Maintenir un inventaire SBOM à jour
- Supprimer les dépendances non utilisées

---

## A07:2021 — Identification and Authentication Failures

### Indicateurs
- Mots de passe faibles sans politique de complexité
- Absence de rate limiting / captcha sur login
- Sessions non invalidées après logout
- Identifiants de session dans l'URL
- User enumeration possible (réponses différentes)

### Remédiation
- Imposer MFA (TOTP, WebAuthn)
- Rate limiting strict sur auth endpoints
- Verrouillage après N tentatives
- Hachage fort : bcrypt, scrypt, Argon2id
- Rotation des identifiants de session après login

---

## A08:2021 — Software and Data Integrity Failures

### Description
Mises à jour logicielles, données critiques ou pipelines CI/CD compromis.

### Indicateurs
- Dépendances téléchargées sans vérification de signature
- Pipelines CI/CD exposant des secrets
- Désérialisation de données non fiables (Pickle, YAML unsafe_load)

### Remédiation
- Vérifier les signatures des packages
- Registres privés pour images Docker
- Ne jamais désérialiser des données non fiables
- Signer les commits Git (GPG/SSH)

---

## A09:2021 — Security Logging and Monitoring Failures

### Description
Absence de journalisation empêchant la détection d'intrusions.

### Indicateurs
- Pas de logs pour tentatives de login échouées
- Pas d'alertes sur modifications de comptes privilégiés
- Logs stockés localement (modifiables par attaquant)
- Logs incomplets (pas d'IP source, user-agent, timestamp)

### Remédiation
- Logger : auth (succès/échec), changements de privilèges, accès données sensibles
- Format JSON standardisé avec timestamp ISO 8601
- Centraliser vers SIEM avec alertes temps réel
- Protéger l'intégrité des logs (append-only)

---

## A10:2021 — Server-Side Request Forgery (SSRF)

### Description
L'application récupère une ressource distante sans valider l'URL fournie.

### Indicateurs
- Paramètres `url=`, `path=`, `redirect=` acceptant URLs arbitraires
- Scan de ports internes : `http://localhost:22`, `http://169.254.169.254/`
- Accès fichiers locaux : `file:///etc/passwd`
- Contournement de filtres : encodage URL double, DNS rebinding

### Remédiation
- Liste blanche de domaines/ports autorisés
- Désactiver les schémas : `file://`, `gopher://`, `ftp://`
- Bloquer les IPs internes : 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Ne pas transmettre les réponses brutes au client

---
## Références
- https://owasp.org/www-project-top-ten/
- https://cheatsheetseries.owasp.org/
