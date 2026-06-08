import paramiko
import os
import json
import socket
from datetime import datetime

def run_remote_privesc_audit(host, username, password=None, key_path=None, port=22):
    """
    Se connecte à une machine distante via SSH, exécute un script d'audit de sécurité
    local (Privilege Escalation & CIS-like) et renvoie les résultats sous forme structurée.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_path and os.path.exists(key_path):
            private_key = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, port=port, username=username, pkey=private_key, timeout=15)
        else:
            client.connect(host, port=port, username=username, password=password, timeout=15)
    except Exception as e:
        return {"success": False, "error": f"Connexion SSH échouée : {str(e)}"}

    audit_script = """#!/bin/bash
echo "=== SYSTEM_INFO ==="
uname -a
cat /etc/issue 2>/dev/null || cat /etc/os-release 2>/dev/null
echo "=== USER_GROUPS ==="
id
whoami
echo "=== SUDO_PERMS ==="
sudo -n -l 2>/dev/null || echo "Sudo nécessite mot de passe ou indisponible"
echo "=== SUID_SGID ==="
find / -perm -4000 -type f 2>/dev/null | head -n 40
echo "=== LINUX_CAPABILITIES ==="
getcap -r / 2>/dev/null | head -n 30
echo "=== LISTEN_PORTS ==="
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || cat /proc/net/tcp 2>/dev/null
echo "=== DOCKER_SOCKET ==="
ls -la /var/run/docker.sock 2>/dev/null || echo "Pas de socket Docker accessible"
echo "=== ENV_VARIABLES ==="
env 2>/dev/null | grep -E -i "key|pass|token|secret|admin|auth" | head -n 25
echo "=== SHELL_HISTORY ==="
tail -n 50 ~/.bash_history ~/.zsh_history 2>/dev/null | grep -E -i "pass|admin|login|ssh|sudo|key" | head -n 20
echo "=== CRON_JOBS ==="
ls -la /etc/cron* /etc/crontab 2>/dev/null
echo "=== WRITABLE_DIRECTORIES ==="
find / -writable -type d 2>/dev/null | grep -E -v "/proc|/sys|/dev|/run|/var|/tmp" | head -n 30
echo "=== SENSITIVE_FILES ==="
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.key" -o -name "wp-config.php" -o -name "config.json" -o -name ".env" 2>/dev/null | grep -E -v "/usr/share|/usr/lib" | head -n 25
echo "=== KERNEL_EXPLOITS_CHECK ==="
kernel_version=$(uname -r)
echo "Noyau détecté : $kernel_version"
"""
    
    try:
        # Exécuter le script
        stdin, stdout, stderr = client.exec_command("bash")
        stdin.write(audit_script)
        stdin.close()
        
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        client.close()
        
        # Structurer les résultats par section
        sections = {}
        current_section = "general"
        sections[current_section] = []
        
        for line in output.splitlines():
            if line.startswith("=== ") and line.endswith(" ==="):
                current_section = line.replace("=== ", "").replace(" ===", "").lower()
                sections[current_section] = []
            else:
                sections[current_section].append(line)
                
        # Formater en texte structuré
        structured_text = []
        for sec, lines in sections.items():
            structured_text.append(f"### Section: {sec.upper()}")
            structured_text.append("\n".join(lines))
            structured_text.append("\n")
            
        return {
            "success": True,
            "raw_output": output,
            "structured_output": "\n".join(structured_text),
            "sections": sections
        }
        
    except Exception as e:
        client.close()
        return {"success": False, "error": f"Erreur lors de l'exécution de l'audit : {str(e)}"}

