#!/usr/bin/env python3
import subprocess
import json
import argparse
import sys
import os
import markdown
import re
from weasyprint import HTML, CSS
import requests
import rag
import base64
import report_config

def run_command(cmd, timeout=None):
    """Exécute une commande système et retourne sa sortie standard."""
    print(f"[*] Exécution de : {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            # On n'affiche l'erreur que si ce n'est pas Nmap (Nmap retourne parfois des codes d'erreur mineurs)
            if cmd[0] != "nmap":
                print(f"[!] Erreur lors de l'exécution: {result.stderr}")
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] La commande a expiré (timeout de {timeout}s)")
        return ""
    except FileNotFoundError:
        print(f"[!] Commande non trouvée: {cmd[0]}")
        raise RuntimeError(f"Commande non trouvée: {cmd[0]}")

def discover_active_hosts(target, nmap_mode="T4", use_agressive=False, use_vuln_script=False, evasion_options=None, ssh_credentials=None):
    """Exécute un scan Nmap et retourne une liste des IPs ayant au moins un port ouvert."""
    
    cmd = ["nmap"]
    
    # Mode de scan (vitesse/profondeur)
    if nmap_mode == "Fast":
        cmd.append("-F")
    elif nmap_mode == "Full":
        cmd.append("-p-")
    else:
        cmd.append("--top-ports")
        cmd.append("1000")
        
    cmd.extend(["-T4", "--open", "-oG", "-"])
    
    if use_agressive:
        cmd.append("-A")
        
    if use_vuln_script:
        cmd.extend(["--script", "vuln"])

    # Évasion de pare-feu (Firewall Evasion)
    if evasion_options:
        if evasion_options.get("fragment"):
            cmd.append("-f")
        if evasion_options.get("decoy"):
            cmd.extend(["-D", evasion_options.get("decoy")])
        if evasion_options.get("spoof_mac"):
            cmd.extend(["--spoof-mac", evasion_options.get("spoof_mac")])

    # Authentification SSH
    if ssh_credentials:
        username = ssh_credentials.get("username")
        password = ssh_credentials.get("password")
        key_path = ssh_credentials.get("key_path")
        script_args = []
        if username:
            script_args.append(f"ssh.username={username}")
        if password:
            script_args.append(f"ssh.password={password}")
        if key_path:
            script_args.append(f"ssh.key={key_path}")
        if script_args:
            cmd.extend(["--script-args", ",".join(script_args)])
        
    cmd.append(target)
    
    stdout = run_command(cmd)
    
    active_hosts = []
    
    for line in stdout.split('\n'):
        if line.startswith("Host:"):
            parts = line.split('\t')
            host_info = parts[0]
            ip = host_info.split(' ')[1]
            
            for p in parts:
                if p.startswith("Ports: "):
                    ports_info = p[7:]
                    open_ports = []
                    for port_str in ports_info.split(','):
                        if '/open/' in port_str:
                            port_num = port_str.strip().split('/')[0]
                            open_ports.append(port_num)
                    
                    # On garde la machine si elle a n'importe quel port ouvert
                    if open_ports:
                        active_hosts.append(ip)
                    break
                    
    return active_hosts

def scan_nuclei(targets_list, selected_tags=None, headers=None):
    """Exécute Nuclei sur une liste de cibles et retourne les résultats en JSON."""
    targets_file = "live_targets.txt"
    with open(targets_file, "w") as f:
        for t in targets_list:
            f.write(t + "\n")
            
    output_file = "nuclei_results.json"
    if os.path.exists(output_file):
        os.remove(output_file)
        
    cmd = ["nuclei", "-l", targets_file, "-json-export", output_file, "-ni"]
    
    # Charger la configuration autotune si disponible
    concurrency = 25
    rate_limit = 100
    if os.path.exists("autotune_config.json"):
        try:
            with open("autotune_config.json", "r") as f_tune:
                tune_cfg = json.load(f_tune)
                concurrency = tune_cfg.get("nuclei_concurrency", concurrency)
                rate_limit = tune_cfg.get("nuclei_rate_limit", rate_limit)
        except Exception:
            pass
    cmd.extend(["-c", str(concurrency), "-rl", str(rate_limit)])
    
    if selected_tags:
        tags_str = ",".join(selected_tags)
        cmd.extend(["-tags", tags_str])

    # Ajouter les en-têtes d'authentification personnalisés (HTTP Headers / Cookies)
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        
    run_command(cmd)
    
    results = []
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            try:
                json_data = json.load(f)
                if not isinstance(json_data, list):
                    json_data = [json_data]
            except json.JSONDecodeError:
                f.seek(0)
                json_data = []
                for line in f:
                    try:
                        json_data.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass

            for data in json_data:
                if not isinstance(data, dict):
                    continue
                    
                severity = data.get("info", {}).get("severity", "").lower()
                # On ignore les failles purement informatives pour ne garder que les vrais risques
                if severity in ["info", "unknown", ""]:
                    continue
                    
                filtered_data = {
                    "template-id": data.get("template-id"),
                    "info": {
                        "name": data.get("info", {}).get("name"),
                        "severity": severity,
                        "description": data.get("info", {}).get("description")
                    },
                    "type": data.get("type"),
                    "host": data.get("host"),
                    "matched-at": data.get("matched-at")
                }
                results.append(filtered_data)
                    
    return results

def analyze_with_ollama(target_desc, nuclei_results, language="Français"):
    """Envoie les résultats à la CrewIA (Multi-Agents) pour génération du rapport."""
    import agents
    
    # 1. Extraction des noms de vulnérabilités pour requêter le RAG
    rag_context = ""
    try:
        vuln_names = [v['info']['name'] for v in nuclei_results if 'info' in v and 'name' in v['info']]
        if vuln_names:
            query_str = " ".join(vuln_names[:3])
            rag_context = rag.query_rag(query_str, n_results=3)
    except Exception as e:
        print(f"[!] Avertissement RAG: {e}")

    # 2. Lancement de l'équipe d'agents (CrewAI)
    print(f"[*] Lancement de l'équipe d'Agents (CrewAI) pour analyse. Veuillez patienter...")
    
    try:
        markdown_report = agents.run_cyber_crew(target_desc, nuclei_results, rag_context, language=language)
        return markdown_report
    except Exception as e:
        print(f"[!] Erreur de la CrewAI: {e}")
        raise RuntimeError(f"Erreur CrewAI: {e}. Vérifiez qu'Ollama est bien lancé.")

def export_to_pdf(markdown_text, output_filename):
    """Convertit le Markdown en HTML puis génère un PDF."""
    print(f"[*] Génération du rapport PDF : {output_filename}")
    
    # Charger la configuration de personnalisation
    rep_cfg = report_config.load_report_config()
    company_name = rep_cfg.get("company_name", "Sentient AI")
    primary_color = rep_cfg.get("primary_color", "#7c3aed")
    footer_text = rep_cfg.get("footer_text", "Sentient AI - Rapport d'Audit Automatisé")
    logo_path = rep_cfg.get("logo_path", "")
    
    # Encodage du logo en base64 pour injection HTML
    logo_base64 = ""
    if logo_path and os.path.exists(logo_path):
        try:
            with open(logo_path, "rb") as f:
                img_data = f.read()
                mime_type = "image/png"
                if logo_path.lower().endswith(".jpg") or logo_path.lower().endswith(".jpeg"):
                    mime_type = "image/jpeg"
                logo_base64 = f"data:{mime_type};base64," + base64.b64encode(img_data).decode('utf-8')
        except Exception as e:
            print(f"[!] Impossible d'encoder le logo : {e}")

    # Nettoyage Markdown
    markdown_text = re.sub(r'```json', '```', markdown_text)
    
    # Convertir en HTML
    html_body = markdown.markdown(markdown_text, extensions=['fenced_code', 'tables'])
    
    # En-tête de page personnalisé (SaaS White-Label)
    header_html = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid {primary_color}; padding-bottom: 15px; margin-bottom: 30px;">
        <div style="flex: 1;">
            <h2 style="margin: 0; padding: 0; border: none; color: #2c3e50; font-size: 18pt; font-weight: 800;">{company_name}</h2>
            <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 9pt;">Rapport d'Évaluation de Sécurité</p>
        </div>
    """
    
    if logo_base64:
        header_html += f"""
        <div style="text-align: right;">
            <img src="{logo_base64}" style="max-height: 45px; max-width: 140px; object-fit: contain;">
        </div>
        """
    header_html += "</div>"
    
    # Surcharge CSS à la volée
    custom_css = f"""
    <style>
        h1 {{
            color: {primary_color} !important;
            border-bottom: 3px solid {primary_color} !important;
        }}
        h3 {{
            color: {primary_color} !important;
        }}
        @page {{
            @bottom-left {{
                content: "{footer_text}";
                font-family: 'Inter', sans-serif;
                font-size: 8pt;
                color: #7f8c8d;
            }}
        }}
    </style>
    """
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Vulnérabilités</title>
        {custom_css}
    </head>
    <body>
        {header_html}
        {html_body}
    </body>
    </html>
    """
    
    try:
        HTML(string=html_content).write_pdf(output_filename, stylesheets=[CSS("style.css")])
        print(f"[+] Rapport généré avec succès : {output_filename}")
    except Exception as e:
        print(f"[!] Erreur lors de la génération PDF : {e}")

def run_recon_pipeline(target, run_subfinder=False, run_gobuster=False):
    """Exécute des outils de reconnaissance supplémentaires (subfinder, gobuster)."""
    recon_results = []
    
    if run_subfinder:
        print(f"[*] Lancement de subfinder sur la cible : {target}")
        cmd = ["subfinder", "-d", target, "-silent"]
        try:
            output = run_command(cmd)
            subdomains = [line.strip() for line in output.split("\n") if line.strip()]
            print(f"[+] Sous-domaines découverts par subfinder : {subdomains}")
            recon_results.extend(subdomains)
        except Exception as e:
            print(f"[!] Erreur subfinder : {e}")
            
    if run_gobuster:
        # Assurer que la cible commence par http
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"
        print(f"[*] Lancement de gobuster sur la cible : {url}")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "./assets/common_wordlist.txt"
            os.makedirs("./assets", exist_ok=True)
            with open(wordlist, "w") as wf:
                wf.write("admin\n.git\nconfig\nbackup\nwp-admin\nlogin\napi\n")
                
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-z"]
        try:
            output = run_command(cmd)
            paths = []
            for line in output.split("\n"):
                if line.strip():
                    paths.append(line.strip())
            print(f"[+] Chemins découverts par gobuster : {paths}")
        except Exception as e:
            print(f"[!] Erreur gobuster : {e}")
            
    return recon_results

def run_sast_scan(target_path):
    """Exécute un scan SAST avec Bandit (Python) et Semgrep (Général) sur le code source."""
    sast_results = []
    
    # 1. Bandit
    if os.path.exists(target_path):
        print(f"[*] Lancement de Bandit sur le chemin : {target_path}")
        output_file = "bandit_results.json"
        if os.path.exists(output_file):
            os.remove(output_file)
        cmd = ["bandit", "-r", target_path, "-f", "json", "-o", output_file]
        try:
            subprocess.run(cmd, capture_output=True)
        except Exception as e:
            print(f"[!] Erreur d'exécution de Bandit : {e}")
            
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    for issue in data.get("results", []):
                        sast_results.append({
                            "template-id": f"bandit-{issue.get('test_id')}",
                            "info": {
                                "name": f"Bandit SAST: {issue.get('issue_text')}",
                                "severity": issue.get("issue_severity").lower(),
                                "description": f"Fichier: {issue.get('filename')}:{issue.get('line_number')}\nCode: {issue.get('code')}"
                            },
                            "type": "sast",
                            "host": target_path,
                            "matched-at": f"{issue.get('filename')}#L{issue.get('line_number')}"
                        })
            except Exception as e:
                print(f"[!] Erreur lecture rapports Bandit : {e}")
            finally:
                if os.path.exists(output_file):
                    os.remove(output_file)
                
    # 2. Semgrep
    if os.path.exists(target_path):
        print(f"[*] Lancement de Semgrep sur le chemin : {target_path}")
        output_file = "semgrep_results.json"
        if os.path.exists(output_file):
            os.remove(output_file)
        cmd = ["semgrep", "scan", "--config=auto", "--json", "-o", output_file, target_path]
        try:
            subprocess.run(cmd, capture_output=True)
        except Exception as e:
            print(f"[!] Erreur d'exécution de Semgrep : {e}")
            
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        sast_results.append({
                            "template-id": result.get("check_id"),
                            "info": {
                                "name": f"Semgrep SAST: {result.get('extra', {}).get('message')}",
                                "severity": result.get("extra", {}).get("severity", "").lower(),
                                "description": f"Fichier: {result.get('path')}:{result.get('start', {}).get('line')}\nExplication: {result.get('extra', {}).get('metadata', {}).get('description', '')}"
                            },
                            "type": "sast",
                            "host": target_path,
                            "matched-at": f"{result.get('path')}#L{result.get('start', {}).get('line')}"
                        })
            except Exception as e:
                print(f"[!] Erreur lecture rapports Semgrep : {e}")
            finally:
                if os.path.exists(output_file):
                    os.remove(output_file)
                
    return sast_results

def run_trivy_scan(target_image_or_path):
    """Exécute un scan de conteneur ou de filesystem avec Trivy."""
    trivy_results = []
    
    print(f"[*] Lancement de Trivy sur la cible : {target_image_or_path}")
    output_file = "trivy_results.json"
    if os.path.exists(output_file):
        os.remove(output_file)
        
    if os.path.exists(target_image_or_path):
        cmd = ["trivy", "fs", "--format", "json", "--output", output_file, target_image_or_path]
    else:
        cmd = ["trivy", "image", "--format", "json", "--output", output_file, target_image_or_path]
        
    try:
        subprocess.run(cmd, capture_output=True)
    except Exception as e:
        print(f"[!] Erreur d'exécution de Trivy : {e}")
    
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                data = json.load(f)
                for report in data.get("Results", []):
                    target = report.get("Target", "")
                    for vuln in report.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "").lower()
                        if severity in ["info", "unknown", "low"]:
                            continue
                        trivy_results.append({
                            "template-id": vuln.get("VulnerabilityID"),
                            "info": {
                                "name": f"Trivy: {vuln.get('PkgName')} - {vuln.get('Title', 'Vulnerability')}",
                                "severity": severity,
                                "description": f"Package: {vuln.get('PkgName')} (Installed: {vuln.get('InstalledVersion')}, Fixed: {vuln.get('FixedVersion')})\nDescription: {vuln.get('Description')}"
                            },
                            "type": "container",
                            "host": target_image_or_path,
                            "matched-at": f"{target} ({vuln.get('VulnerabilityID')})"
                        })
        except Exception as e:
            print(f"[!] Erreur lecture rapports Trivy : {e}")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
            
    return trivy_results

def main():
    parser = argparse.ArgumentParser(description="PoC Scanner de Vulnérabilités IA (Local)")
    parser.add_argument("target", help="L'adresse IP, le domaine ou la plage CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--output", "-o", default="rapport_vulnerabilites.pdf", help="Nom du fichier PDF de sortie")
    args = parser.parse_args()

    target = args.target
    
    print(f"\n{'='*50}")
    print(f"🚀 Démarrage du PoC AI Red Teaming sur : {target}")
    print(f"{'='*50}\n")
    
    # 1. Nmap Discovery
    print("[*] Étape 1 : Découverte des cibles actives (Nmap)...")
    active_hosts = discover_active_hosts(target)
    
    if not active_hosts:
        print("[!] Aucune cible avec des ports ouverts n'a été détectée.")
        print("[!] Fin de l'audit.")
        sys.exit(0)
        
    print(f"[+] {len(active_hosts)} cible(s) détectée(s) : {', '.join(active_hosts)}")
    
    # 2. Nuclei
    print("\n[*] Étape 2 : Scan de vulnérabilités sur les cibles actives (Nuclei)...")
    nuclei_results = scan_nuclei(active_hosts)
    print(f"[+] {len(nuclei_results)} indicateurs bruts trouvés par Nuclei.")
    
    # 3. Ollama (Triage & Rédaction)
    print("\n[*] Étape 3 : Triage IA et rédaction du rapport (Ollama)...")
    target_desc = f"{target} ({len(active_hosts)} hôte(s) web scanné(s))"
    markdown_report = analyze_with_ollama(target_desc, nuclei_results)
    
    with open("rapport_brut.md", "w", encoding="utf-8") as f:
        f.write(markdown_report)
        
    md_output = args.output.replace('.pdf', '.md')
    if md_output == args.output:
        md_output += ".md"
        
    with open(md_output, "w", encoding="utf-8") as f:
        f.write(markdown_report)
        
    # 4. Export PDF
    print("\n[*] Étape 4 : Exportation...")
    export_to_pdf(markdown_report, args.output)
    
    print(f"\n{'='*50}")
    print("✅ Processus terminé. Consultez le rapport PDF.")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
