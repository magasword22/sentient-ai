# CIS Benchmarks - Synthèse de Durcissement des Serveurs

## 1. Durcissement de l'accès SSH (CIS SSH Benchmark)
* **Chiffrement fort** : Configurer SSH pour utiliser uniquement des ciphers et MAC sécurisés (ex: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`). Désactiver les versions obsolètes du protocole (utiliser uniquement SSHv2).
* **Gestion des sessions** : Définir un temps d'inactivité maximal (`ClientAliveInterval 300` et `ClientAliveCountMax 0`) pour déconnecter automatiquement les sessions inactives.
* **Accès SSH** : Restreindre l'accès à des utilisateurs ou groupes spécifiques à l'aide des directives `AllowUsers` ou `AllowGroups`.

## 2. Configuration Réseau et Noyau (CIS Network Hardening)
* **Paramètres sysctl** : Désactiver le routage de paquets si la machine n'est pas un routeur (`net.ipv4.ip_forward = 0`). Désactiver l'acceptation des redirections ICMP (`net.ipv4.conf.all.accept_redirects = 0`). Désactiver l'acceptation de paquets source-routés (`net.ipv4.conf.all.accept_source_route = 0`).
* **Protection réseau** : Activer la protection contre le spoofing IP (`net.ipv4.conf.all.rp_filter = 1`) et rejeter les paquets ICMP de broadcast pour éviter les attaques par déni de service.

## 3. Gestion des Droits et Système de Fichier (CIS Filesystem Security)
* **Points de montage** : Configurer `/tmp`, `/var/tmp` et `/dev/shm` avec les options `nodev`, `nosuid` et `noexec` pour empêcher l'exécution de binaires malveillants depuis ces répertoires temporaires.
* **Vérification des droits** : Rechercher et corriger régulièrement les fichiers possédant des droits en écriture globale (`world-writable`) ou les fichiers sans propriétaire valide.
* **Intégrité système** : Installer et configurer un système de détection d'intrusion basé sur l'hôte (HIDS) comme AIDE ou Tripwire pour surveiller l'intégrité des fichiers système sensibles.
