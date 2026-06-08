# OWASP Top 10 - Guide de Remédiation et Correctifs

## A01:2021-Broken Access Control (Contrôle d'accès défaillant)
* **Description** : Les utilisateurs peuvent accéder à des ressources en dehors des privilèges qui leur sont normalement attribués.
* **Remédiation** : Imposer le principe du moindre privilège. Valider systématiquement les autorisations du côté serveur pour chaque requête (ne jamais faire confiance aux identifiants passés par le client sans contrôle). Utiliser des identifiants d'objets non prévisibles (UUIDs).

## A02:2021-Cryptographic Failures (Défaillances cryptographiques)
* **Description** : Exposition ou mauvaise protection de données sensibles (mots de passe, numéros de cartes de crédit, informations personnelles) en transit ou au repos.
* **Remédiation** : Chiffrer toutes les données en transit avec TLS 1.3 ou 1.2 uniquement (désactiver TLS 1.0/1.1). Hacher les mots de passe à l'aide d'algorithmes robustes avec sel (Argon2, bcrypt). Ne jamais utiliser de fonctions de hachage obsolètes (MD5, SHA1).

## A03:2021-Injection (Injections SQL, Command Injection, XSS)
* **Description** : Des données fournies par l'utilisateur sont interprétées par un interpréteur sous forme de commandes ou de requêtes.
* **Remédiation** : Utiliser des requêtes préparées et paramétrées pour SQL. Échapper et valider toutes les entrées utilisateurs (filtrage par liste blanche). Pour le XSS, utiliser des moteurs de templates sécurisés et appliquer l'encodage de sortie adéquat (HTML entity encoding).

## A05:2021-Security Misconfiguration (Mauvaise configuration de sécurité)
* **Description** : Configurations par défaut non modifiées, messages d'erreur trop détaillés révélant des informations internes, ports ouverts inutiles.
* **Remédiation** : Désactiver les comptes par défaut et modifier les mots de passe d'usine immédiatement. Désactiver le listage des répertoires Web. Configurer correctement les en-têtes de sécurité (CSP, CORS).

## A06:2021-Vulnerable and Outdated Components (Composants vulnérables et obsolètes)
* **Description** : Utilisation de dépendances (bibliothèques, frameworks) contenant des vulnérabilités connues sans mise à jour.
* **Remédiation** : Analyser en continu les dépendances à l'aide d'outils SAST/SCA (Software Composition Analysis) comme Dependency-Check ou Trivy. Mettre à jour régulièrement les paquets.
