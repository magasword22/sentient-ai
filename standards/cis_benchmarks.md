# CIS Benchmarks — Synthèse de Durcissement des Serveurs Linux

> Source : Center for Internet Security (CIS) Benchmarks v8
> Cibles : Ubuntu 22.04 LTS, Debian 12, RHEL 9, Rocky Linux 9

---

## 1. Durcissement SSH

### 1.1 Configuration sécurisée (/etc/ssh/sshd_config)
```bash
# Version du protocole
Protocol 2

# Désactiver l'authentification par mot de passe
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes

# Désactiver le login root direct
PermitRootLogin no

# Algorithmes de chiffrement robustes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

# Session timeout
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
MaxAuthTries 3
MaxSessions 5

# Restreindre l'accès
AllowUsers adminuser
AllowGroups ssh-users

# Bannière légale
Banner /etc/issue.net

# Désactiver le forwarding non nécessaire
AllowTcpForwarding no
X11Forwarding no
```

---

## 2. Configuration Réseau et Noyau (sysctl)

### 2.1 Paramètres réseau sécuritaires (/etc/sysctl.d/99-cis.conf)
```bash
# Désactiver le routage IP
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Protection anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorer les requêtes ICMP broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Activer les SYN cookies (protection SYN flood)
net.ipv4.tcp_syncookies = 1

# Désactiver les redirections ICMP
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Désactiver le source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignorer les ICMP redirects envoyés
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Protection contre le martien packets (adresses IP non routables)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Timeout TCP plus agressif pour libérer les sockets
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Désactiver IPv6 si non utilisé
# net.ipv6.conf.all.disable_ipv6 = 1
```

---

## 3. Sécurité du Système de Fichiers

### 3.1 Options de montage sécurisées (/etc/fstab)
```bash
# Partition /tmp
tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0

# Partition /var/tmp
# Bind mount depuis /tmp pour hériter des restrictions
/tmp /var/tmp none rw,nodev,nosuid,noexec,bind 0 0

# Partition /home (si séparée)
UUID=xxxx /home ext4 defaults,nodev,nosuid 0 2

# Partition /dev/shm
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
```

### 3.2 Permissions des fichiers critiques
```bash
# Passwd et shadow
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group

# Bootloader GRUB
chmod 600 /boot/grub2/grub.cfg  # RHEL
chmod 600 /boot/grub/grub.cfg   # Debian/Ubuntu

# Cron
chmod 600 /etc/crontab
chmod 600 /etc/cron.hourly
chmod 600 /etc/cron.daily
chmod 600 /etc/cron.weekly
chmod 600 /etc/cron.monthly

# Autorisations sudo
chmod 440 /etc/sudoers
chmod 440 /etc/sudoers.d/*
```

### 3.3 Intégrité système
- Installer AIDE (Advanced Intrusion Detection Environment) :
  ```bash
  apt install aide  # Debian/Ubuntu
  dnf install aide  # RHEL/Rocky
  aide --init
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
  # Planifier une vérification quotidienne via cron
  ```
- Configurer les vérifications d'intégrité des packages :
  ```bash
  rpm -Va  # RHEL — vérifie tous les packages
  dpkg --verify  # Debian/Ubuntu
  ```

---

## 4. Gestion des Utilisateurs et Authentification

### 4.1 Politique de mot de passe (/etc/security/pwquality.conf)
```bash
minlen = 12           # Longueur minimale
dcredit = -1          # Au moins 1 chiffre
ucredit = -1          # Au moins 1 majuscule
lcredit = -1          # Au moins 1 minuscule
ocredit = -1          # Au moins 1 caractère spécial
minclass = 4          # Au moins 4 classes de caractères différentes
maxrepeat = 3         # Maximum 3 caractères identiques consécutifs
maxclassrepeat = 4    # Maximum 4 caractères de la même classe
dictcheck = 1         # Vérification contre dictionnaire
```

### 4.2 Verrouillage de compte (/etc/security/faillock.conf)
```bash
deny = 5              # Verrouiller après 5 échecs
unlock_time = 1800    # Déverrouiller après 30 minutes
fail_interval = 900   # Intervalle de 15 minutes pour compter les échecs
```

### 4.3 Limites de sécurité (/etc/security/limits.conf)
```bash
* hard core 0                    # Désactiver les core dumps
* hard maxlogins 10              # Maximum 10 sessions simultanées
* hard nproc 4096                # Limiter les processus par utilisateur
```

---

## 5. Journalisation et Audit

### 5.1 Configuration auditd (/etc/audit/rules.d/cis.rules)
```bash
# Surveiller les modifications de fichiers critiques
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo

# Surveiller l'exécution de commandes privilégiées
-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd
-a always,exit -F arch=b32 -S execve -F euid=0 -k rootcmd

# Surveiller les changements d'horloge système
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Surveiller les modifications de configuration réseau
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/hosts -p wa -k network
-w /etc/sysconfig/network -p wa -k network
```

### 5.2 Configuration rsyslog (centralisation)
```bash
# Envoyer les logs vers un serveur SIEM distant via TCP chiffré (TLS)
*.* @@(o)192.168.10.50:6514

# Formats de sortie
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
```

---

## 6. Services et Applications

### 6.1 Désactivation des services inutiles
```bash
systemctl disable --now avahi-daemon   # Zeroconf/mDNS
systemctl disable --now cups            # Serveur d'impression
systemctl disable --now rpcbind         # RPC (NFS)
systemctl disable --now bluetooth       # Bluetooth
systemctl disable --now autofs          # Montage automatique
```

### 6.2 Sécurisation de la pile cron
- Restreindre l'accès à crontab :
  ```bash
  echo "root" > /etc/cron.allow
  echo "admin" >> /etc/cron.allow
  rm -f /etc/cron.deny
  ```
- Vérifier régulièrement les tâches cron des utilisateurs

---
## Références
- CIS Benchmarks : https://www.cisecurity.org/cis-benchmarks/
- CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0
- CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0
