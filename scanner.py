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

def discover_active_hosts(target, nmap_mode="T4", use_agressive=False, use_vuln_script=False):
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

def scan_nuclei(targets_list, selected_tags=None):
    """Exécute Nuclei sur une liste de cibles et retourne les résultats en JSON."""
    targets_file = "live_targets.txt"
    with open(targets_file, "w") as f:
        for t in targets_list:
            f.write(t + "\n")
            
    output_file = "nuclei_results.json"
    if os.path.exists(output_file):
        os.remove(output_file)
        
    cmd = ["nuclei", "-l", targets_file, "-json-export", output_file, "-ni"]
    
    if selected_tags:
        tags_str = ",".join(selected_tags)
        cmd.extend(["-tags", tags_str])
        
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

def analyze_with_ollama(target_desc, nuclei_results):
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
        markdown_report = agents.run_cyber_crew(target_desc, nuclei_results, rag_context)
        return markdown_report
    except Exception as e:
        print(f"[!] Erreur de la CrewAI: {e}")
        raise RuntimeError(f"Erreur CrewAI: {e}. Vérifiez qu'Ollama est bien lancé.")

def export_to_pdf(markdown_text, output_filename):
    """Convertit le Markdown en HTML puis génère un PDF."""
    print(f"[*] Génération du rapport PDF : {output_filename}")
    
    markdown_text = re.sub(r'```json', '```', markdown_text)
    html_body = markdown.markdown(markdown_text, extensions=['fenced_code', 'tables'])
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport de Vulnérabilités</title>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """
    
    try:
        HTML(string=html_content).write_pdf(output_filename, stylesheets=[CSS("style.css")])
        print(f"[+] Rapport généré avec succès : {output_filename}")
    except Exception as e:
        print(f"[!] Erreur lors de la génération PDF : {e}")

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
    
    with open("rapport_brut.md", "w") as f:
        f.write(markdown_report)
        
    # 4. Export PDF
    print("\n[*] Étape 4 : Exportation...")
    export_to_pdf(markdown_report, args.output)
    
    print(f"\n{'='*50}")
    print("✅ Processus terminé. Consultez le rapport PDF.")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
