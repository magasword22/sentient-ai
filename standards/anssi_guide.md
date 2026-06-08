# Recommandations de sécurité de l'ANSSI (Durcissement et Bonnes Pratiques)

## 1. Durcissement des systèmes GNU/Linux (Guide ANSSI BP-028)
* **Politique d'accès et d'authentification** : Désactiver le compte `root` pour les connexions SSH directes (`PermitRootLogin no`). Utiliser l'authentification par clé publique uniquement et appliquer des permissions strictes sur les clés (`0600`).
* **Cloisonnement réseau** : Mettre en œuvre un pare-feu local (iptables/nftables) et appliquer une politique par défaut de rejet (`DROP`) sur toutes les chaînes d'entrée (`INPUT`).
* **Mises à jour de sécurité** : Mettre en place des mécanismes de mise à jour automatique pour les correctifs critiques de sécurité (ex: `unattended-upgrades`).
* **Journalisation** : Centraliser les journaux de sécurité (syslog/journald) vers un serveur de logs distant et sécurisé (SIEM).

## 2. Sécurisation Active Directory (Guide ANSSI BP-042)
* **Modèle d'administration à trois tiers (Tiering)** : Séparer strictement les comptes d'administration d'Active Directory. Les administrateurs de niveau Tier 0 (Contrôleurs de Domaine) ne doivent jamais se connecter sur des machines de niveau Tier 1 (Serveurs d'applications) ou Tier 2 (Postes de travail).
* **Mots de passe** : Imposer des politiques de mot de passe fortes (longueur minimale de 15 caractères, complexité, protection contre l'utilisation de mots de passe compromis).
* **Délégation de privilèges** : Limiter au strict minimum les membres des groupes `Administrateurs de l'entreprise` et `Administrateurs du domaine`.

## 3. Sécurisation des serveurs Web et applications
* **Principes généraux** : Minimiser les services installés, désactiver les signatures de serveurs (ex: `ServerSignature Off` dans Apache/Nginx), désactiver les méthodes HTTP inutilisées (TRACE, TRACK) et mettre en œuvre les en-têtes HTTP de sécurité (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
