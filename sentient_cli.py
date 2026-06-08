#!/usr/bin/env python3
import sys
import argparse
import json
import os
from datetime import datetime

# Importer les modules de Sentient AI
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scanner import discover_active_hosts, scan_nuclei, analyze_with_ollama, run_sast_scan, run_trivy_scan

def export_to_sarif(nuclei_results, target):
    """Génère un rapport au format SARIF pour l'intégration CI/CD."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentient AI",
                        "informationUri": "https://github.com/magsword22/sentient",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }
    
    rules = []
    rule_ids = set()
    results = []
    
    for r in nuclei_results:
        vuln_id = r.get("template-id", "unknown-vuln")
        vuln_name = r.get("info", {}).get("name", "Vulnerability")
        severity = r.get("info", {}).get("severity", "medium").upper()
        desc = r.get("info", {}).get("description", vuln_name)
        host = r.get("host", target)
        matched = r.get("matched-at", host)
        
        # Sévérité SARIF
        level = "warning"
        if severity in ["CRITICAL", "HIGH"]:
            level = "error"
        elif severity == "LOW":
            level = "note"
            
        if vuln_id not in rule_ids:
            rule_ids.add(vuln_id)
            rules.append({
                "id": vuln_id,
                "shortDescription": {"text": vuln_name},
                "fullDescription": {"text": desc}
            })
            
        results.append({
            "ruleId": vuln_id,
            "level": level,
            "message": {
                "text": f"Vulnerability detected on host: {host}. Matched at: {matched}."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": matched
                        }
                    }
                }
            ]
        })
        
    sarif["runs"][0]["tool"]["driver"]["rules"] = rules
    sarif["runs"][0]["results"] = results
    return sarif

def main():
    parser = argparse.ArgumentParser(description="Sentient AI CLI - Outil d'audit de sécurité local pour l'intégration CI/CD")
    parser.add_argument("--target", required=True, help="Cible à auditer (IP, domaine ou dossier de code)")
    parser.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown", help="Format de sortie (default: markdown)")
    parser.add_argument("--sast", action="store_true", help="Activer le scan statique (Semgrep/Bandit) sur la cible")
    parser.add_argument("--trivy", action="store_true", help="Activer le scan de conteneur/filesystem (Trivy)")
    parser.add_argument("--evasion", action="store_true", help="Activer les techniques d'évasion de pare-feu Nmap")
    parser.add_argument("--lang", default="Français", help="Langue du rapport IA (default: Français)")
    parser.add_argument("--output", help="Chemin du fichier de sortie")
    
    args = parser.parse_args()
    
    print(f"[*] Sentient AI - Démarrage du scan sur : {args.target}", file=sys.stderr)
    
    # 1. Découverte et Scan
    active_hosts = []
    nuclei_results = []
    
    if args.sast:
        print("[*] Lancement du scan SAST...", file=sys.stderr)
        sast_res = run_sast_scan(args.target)
        nuclei_results.extend(sast_res)
        
    if args.trivy:
        print("[*] Lancement du scan Trivy...", file=sys.stderr)
        trivy_res = run_trivy_scan(args.target)
        nuclei_results.extend(trivy_res)
        
    # Nmap & Nuclei
    if not args.sast and not args.trivy:
        print("[*] Découverte d'hôtes Nmap...", file=sys.stderr)
        nmap_mode = "aggressif" if args.evasion else "rapide"
        active_hosts = discover_active_hosts(args.target, nmap_mode=nmap_mode)
        print(f"[*] Hôtes actifs trouvés : {active_hosts}", file=sys.stderr)
        
        if active_hosts:
            print("[*] Lancement du scan Nuclei...", file=sys.stderr)
            nuclei_results = scan_nuclei(active_hosts)
            
    print(f"[*] Scan terminé. {len(nuclei_results)} failles détectées.", file=sys.stderr)
    
    # 2. Formater la sortie
    if args.format == "json":
        output_content = json.dumps(nuclei_results, indent=2)
    elif args.format == "sarif":
        output_content = json.dumps(export_to_sarif(nuclei_results, args.target), indent=2)
    else:
        # Analyse IA par défaut
        print("[*] Lancement de l'orchestration multi-agents IA pour le rapport...", file=sys.stderr)
        target_desc = f"{args.target} CLI"
        output_content = analyze_with_ollama(target_desc, nuclei_results, language=args.lang)
        
    # 3. Écrire le livrable
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"[*] Rapport enregistré dans : {args.output}", file=sys.stderr)
    else:
        print(output_content)

if __name__ == "__main__":
    main()
