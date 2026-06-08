import paramiko
import os
import json
import socket
import random
from datetime import datetime

def run_remote_privesc_audit(host, username, password=None, key_path=None, port=22):
    """
    Se connecte à une machine distante via SSH, détecte l'OS (Linux, macOS, Windows),
    exécute un script d'audit local de sécurité (PrivEsc & CIS-like) et renvoie les résultats.
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

    # 1. Détection de l'OS cible
    detected_os = "Linux"
    try:
        stdin, stdout, stderr = client.exec_command("uname -s")
        os_name = stdout.read().decode('utf-8').strip()
        if "Linux" in os_name:
            detected_os = "Linux"
        elif "Darwin" in os_name:
            detected_os = "macOS"
        else:
            # Essayer de détecter Windows
            stdin, stdout, stderr = client.exec_command("cmd.exe /c ver")
            win_ver = stdout.read().decode('utf-8').strip()
            if "Windows" in win_ver or "Microsoft" in win_ver:
                detected_os = "Windows"
    except Exception:
        # Fallback par défaut
        detected_os = "Linux"

    # 2. Scripts d'audit ciblés par OS
    if detected_os == "macOS":
        audit_script = """#!/bin/bash
echo "=== SYSTEM_INFO ==="
sw_vers
uname -a
echo "=== SIP_STATUS ==="
csrutil status 2>/dev/null || echo "Impossible de lire le statut SIP"
echo "=== USER_GROUPS ==="
id
dscl . -read /Users/$(whoami) PrimaryGroupID RealName 2>/dev/null
echo "=== SUDO_PERMS ==="
sudo -n -l 2>/dev/null || echo "Sudo nécessite mot de passe ou est indisponible"
echo "=== SUID_SGID ==="
find /System/Volumes/Data -perm -4000 -type f 2>/dev/null | head -n 30 || find / -perm -4000 -type f 2>/dev/null | head -n 30
echo "=== LISTEN_PORTS ==="
lsof -i -P -n | grep LISTEN | head -n 30
echo "=== INSTALLED_BREW ==="
brew list --versions 2>/dev/null | head -n 40 || echo "Homebrew non installé ou inaccessible"
echo "=== ENV_VARIABLES ==="
env 2>/dev/null | grep -E -i "key|pass|token|secret|admin|auth" | head -n 20
echo "=== SHELL_HISTORY ==="
tail -n 50 ~/.bash_history ~/.zsh_history ~/.bash_profile ~/.zshrc 2>/dev/null | grep -E -i "pass|admin|login|ssh|sudo|key" | head -n 20
echo "=== SENSITIVE_FILES ==="
find ~ -name "id_rsa" -o -name "*.key" -o -name ".env" -o -name "config.json" -o -name "*.db" -o -name "*.bak" -o -name "*.sql" 2>/dev/null | head -n 30
echo "=== SSH_AWS_PERMS ==="
ls -la ~/.ssh ~/.aws 2>/dev/null
"""
        shell_cmd = "bash"

    elif detected_os == "Windows":
        # Script PowerShell exécuté via la ligne de commande Windows
        audit_script = """powershell -NoProfile -ExecutionPolicy Bypass -Command "
Write-Host '=== SYSTEM_INFO ==='
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List
Write-Host '=== USER_GROUPS ==='
whoami /groups
Write-Host '=== HOTFIXES ==='
Get-HotFix | Select-Object HotFixID, Description, InstalledOn | Select-Object -First 10 | Format-Table
Write-Host '=== INSTALLED_SOFTWARE ==='
Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion | Select-Object -First 20 | Format-Table
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion | Select-Object -First 20 | Format-Table
Write-Host '=== LISTEN_PORTS ==='
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Select-Object -First 20 | Format-Table
Write-Host '=== ALWAYS_INSTALL_ELEVATED ==='
Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
Write-Host '=== WINDOWS_AUTOLOGON ==='
Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue | Select-Object DefaultUserName, DefaultPassword, AutoAdminLogon | Format-List
Write-Host '=== UNQUOTED_SERVICE_PATHS ==='
Get-WmiObject win32_service | Where-Object { $_.PathName -notlike '\"*' -and $_.PathName -like '* *' -and $_.PathName -notlike '*\\system32\\*' } | Select-Object Name, PathName | Format-Table
Write-Host '=== SENSITIVE_FILES ==='
Get-ChildItem -Path C:\\Users\\ -Filter '*.git' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
Get-ChildItem -Path C:\\Users\\ -Filter 'id_rsa' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
Get-ChildItem -Path C:\\Users\\ -Filter '*.env' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
Get-ChildItem -Path C:\\Users\\ -Filter '*.bak' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
Write-Host '=== ENV_VARIABLES ==='
Get-ChildItem Env: | Where-Object { $_.Name -match 'key|pass|token|secret|admin|auth' } | Select-Object Name, Value | Format-Table
Write-Host '=== POWERSHELL_HISTORY ==='
Get-Content -Path \\\"$env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\\\" -ErrorAction SilentlyContinue | Select-Object -Last 50 | Select-String 'pass|admin|login|key' | Select-Object -First 20
" """
        shell_cmd = "cmd.exe"

    else: # Linux
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
echo "=== INSTALLED_PACKAGES ==="
dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | head -n 40 || rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null | head -n 40 || apk info -v 2>/dev/null | head -n 40
echo "=== SSH_CONFIG ==="
cat /etc/ssh/sshd_config 2>/dev/null | grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication" | grep -v "#"
echo "=== ENV_VARIABLES ==="
env 2>/dev/null | grep -E -i "key|pass|token|secret|admin|auth" | head -n 20
echo "=== SHELL_HISTORY ==="
tail -n 100 ~/.bash_history ~/.zsh_history 2>/dev/null | grep -E -i "pass|admin|login|ssh|sudo|key" | head -n 30
echo "=== CRON_JOBS ==="
ls -la /etc/cron* /etc/crontab 2>/dev/null
echo "=== WRITABLE_DIRECTORIES ==="
find / -writable -type d 2>/dev/null | grep -E -v "/proc|/sys|/dev|/run|/var|/tmp" | head -n 25
echo "=== SENSITIVE_FILES ==="
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.key" -o -name "wp-config.php" -o -name "config.json" -o -name ".env" -o -name "*.bak" -o -name "*.sql" -o -name "*.db" 2>/dev/null | grep -E -v "/usr/share|/usr/lib" | head -n 30
echo "=== SSH_AWS_PERMS ==="
ls -la ~/.ssh ~/.aws 2>/dev/null
echo "=== KERNEL_EXPLOITS_CHECK ==="
kernel_version=$(uname -r)
echo "Noyau détecté : $kernel_version"
"""
        shell_cmd = "bash"

    # 3. Exécution du script via SSH
    try:
        stdin, stdout, stderr = client.exec_command(shell_cmd)
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
            "detected_os": detected_os,
            "raw_output": output,
            "structured_output": "\n".join(structured_text),
            "sections": sections
        }
        
    except Exception as e:
        client.close()
        return {"success": False, "error": f"Erreur lors de l'exécution de l'audit : {str(e)}"}
