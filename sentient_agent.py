#!/usr/bin/env python3
import http.server
import socketserver
import json
import subprocess
import os
import shutil

PORT = 8502
TOKEN = "sentient_secure_token_2026"

def run_sast_scan(target_path):
    """Exécute Semgrep et Bandit localement sur la sonde."""
    results = []
    if not os.path.exists(target_path):
        return results

    # 1. Semgrep
    if shutil.which("semgrep"):
        try:
            cmd = ["semgrep", "--config=auto", "--json", target_path]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            data = json.loads(res.stdout)
            for item in data.get("results", []):
                results.append({
                    "template-id": f"semgrep-{item.get('check_id')}",
                    "info": {
                        "name": f"SAST: {item.get('extra', {}).get('message')}",
                        "severity": item.get("extra", {}).get("severity", "medium").lower(),
                        "description": f"File: {item.get('path')} | Line: {item.get('start', {}).get('line')}"
                    },
                    "type": "sast",
                    "host": target_path,
                    "matched-at": f"{item.get('path')}#L{item.get('start', {}).get('line')}"
                })
        except Exception as e:
            print(f"[!] Semgrep error on probe: {e}")

    # 2. Bandit
    if shutil.which("bandit"):
        try:
            cmd = ["bandit", "-r", "-f", "json", target_path]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
            data = json.loads(res.stdout)
            for item in data.get("results", []):
                results.append({
                    "template-id": f"bandit-{item.get('test_id')}",
                    "info": {
                        "name": f"SAST Bandit: {item.get('issue_text')}",
                        "severity": item.get("issue_severity", "medium").lower(),
                        "description": f"File: {item.get('filename')} | Line: {item.get('line_number')}"
                    },
                    "type": "sast",
                    "host": target_path,
                    "matched-at": f"{item.get('filename')}#L{item.get('line_number')}"
                })
        except Exception as e:
            print(f"[!] Bandit error on probe: {e}")

    return results

def run_trivy_scan(target_image):
    """Exécute Trivy localement sur la sonde."""
    results = []
    if not shutil.which("trivy"):
        return results

    try:
        # Détecter si c'est un chemin local ou une image
        scan_type = "fs" if os.path.exists(target_image) else "image"
        cmd = ["trivy", scan_type, "--format", "json", target_image]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
        data = json.loads(res.stdout)
        
        for report in data.get("Results", []):
            for vuln in report.get("Vulnerabilities", []):
                results.append({
                    "template-id": vuln.get("VulnerabilityID", "trivy-vuln"),
                    "info": {
                        "name": f"Container Vuln: {vuln.get('PkgName')} ({vuln.get('VulnerabilityID')})",
                        "severity": vuln.get("Severity", "medium").lower(),
                        "description": vuln.get("Description", "No description provided.")
                    },
                    "type": "trivy",
                    "host": target_image,
                    "matched-at": f"Package: {vuln.get('PkgName')} | Version: {vuln.get('InstalledVersion')}"
                })
    except Exception as e:
        print(f"[!] Trivy error on probe: {e}")

    return results

class ScannerAgentHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Vérifier l'authentification
        auth_header = self.headers.get("Authorization")
        if not auth_header or auth_header != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return
            
        try:
            params = json.loads(post_data.decode('utf-8'))
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON parameters")
            return
            
        target = params.get("target")
        nmap_mode = params.get("nmap_mode", "rapide")
        nuclei_tags = params.get("nuclei_tags", [])
        run_sast = params.get("sast", False)
        run_trivy = params.get("trivy", False)
        
        if not target:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing target parameter")
            return
            
        print(f"[*] Running remote scan for target: {target} (SAST={run_sast}, Trivy={run_trivy})")
        results = []

        # 1. DevSecOps: SAST & Trivy
        if run_sast:
            results.extend(run_sast_scan(target))
        if run_trivy:
            results.extend(run_trivy_scan(target))

        # 2. Réseau (Nmap & Nuclei)
        if not run_sast and not run_trivy:
            active_hosts = [target]
            if nmap_mode != "aucun":
                try:
                    cmd = ["nmap", "-sn", target]
                    if nmap_mode == "aggressif":
                        cmd = ["nmap", "-O", "-sV", target]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    active_hosts = []
                    for line in res.stdout.splitlines():
                        if "Nmap scan report for" in line:
                            parts = line.split()
                            active_hosts.append(parts[-1].strip("()"))
                    if not active_hosts:
                        active_hosts = [target]
                except Exception as e:
                    print(f"[!] Error running Nmap on probe: {e}")
                    
            if active_hosts:
                try:
                    for host in active_hosts:
                        cmd = ["nuclei", "-target", host, "-json-export", "/tmp/nuclei_out.json"]
                        if nuclei_tags:
                            cmd.extend(["-tags", ",".join(nuclei_tags)])
                        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
                        if os.path.exists("/tmp/nuclei_out.json"):
                            with open("/tmp/nuclei_out.json", "r", encoding="utf-8") as f:
                                for line in f:
                                    if line.strip():
                                        try:
                                            results.append(json.loads(line))
                                        except Exception:
                                            pass
                            os.remove("/tmp/nuclei_out.json")
                except Exception as e:
                    print(f"[!] Error running Nuclei on probe: {e}")
                    
        # Renvoyer les résultats au format JSON
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results).encode('utf-8'))

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Sentient AI Scanner Agent is online.")

def run():
    print(f"[*] Starting Sentient AI Scanner Agent on port {PORT}...")
    with socketserver.TCPServer(("", PORT), ScannerAgentHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run()
