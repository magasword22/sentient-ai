#!/usr/bin/env python3
"""
Sentient AI — Scanner Agent (sonde légère distante)
Déployer sur un VPS/serveur distant pour exécuter Nmap/Nuclei/SAST/Trivy.
Envoie des heartbeats au serveur principal pour le monitoring.

Usage : python3 sentient_agent.py [--master http://serveur:8501] [--name "VPS Paris"]
"""

import http.server
import socketserver
import json
import subprocess
import os
import shutil
import threading
import time
import argparse
import urllib.request

PORT = int(os.environ.get("AGENT_PORT", 8502))
TOKEN = os.environ.get("AGENT_TOKEN", "sentient_secure_token_2026")
MASTER_URL = os.environ.get("MASTER_URL", "")
AGENT_NAME = os.environ.get("AGENT_NAME", "")
_scanning = False
_scan_target = ""

def send_heartbeat():
    """Envoie un heartbeat au serveur principal toutes les 30 secondes."""
    global _scanning, _scan_target
    while True:
        if MASTER_URL:
            try:
                params = f"name={AGENT_NAME}&url=http://{_get_ip()}:{PORT}&scan_active={str(_scanning).lower()}&scan_target={_scan_target}"
                req = urllib.request.Request(f"{MASTER_URL}/api/probes/heartbeat?{params}", method="POST")
                urllib.request.urlopen(req, timeout=5)
            except:
                pass
        time.sleep(30)

def _get_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

def run_sast_scan(target_path):
    results = []
    if not os.path.exists(target_path):
        return results
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
                    "type": "sast", "host": target_path,
                    "matched-at": f"{item.get('path')}#L{item.get('start', {}).get('line')}"
                })
        except Exception as e:
            print(f"[!] Semgrep error: {e}")
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
                    "type": "sast", "host": target_path,
                    "matched-at": f"{item.get('filename')}#L{item.get('line_number')}"
                })
        except Exception as e:
            print(f"[!] Bandit error: {e}")
    return results

def run_trivy_scan(target_image):
    results = []
    if not shutil.which("trivy"):
        return results
    try:
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
                    "type": "trivy", "host": target_image,
                    "matched-at": f"Package: {vuln.get('PkgName')} | Version: {vuln.get('InstalledVersion')}"
                })
    except Exception as e:
        print(f"[!] Trivy error: {e}")
    return results

class ScannerAgentHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global _scanning, _scan_target
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b""

        auth_header = self.headers.get("Authorization", "")
        if not auth_header or auth_header != f"Bearer {TOKEN}":
            self.send_response(401); self.end_headers(); self.wfile.write(b"Unauthorized"); return

        try:
            params = json.loads(post_data.decode('utf-8'))
        except:
            self.send_response(400); self.end_headers(); self.wfile.write(b"Invalid JSON"); return

        target = params.get("target", "")
        nmap_mode = params.get("nmap_mode", "rapide")
        nuclei_tags = params.get("nuclei_tags", [])
        run_sast = params.get("sast", False)
        run_trivy = params.get("trivy", False)

        if not target:
            self.send_response(400); self.end_headers(); self.wfile.write(b"Missing target"); return

        _scanning = True; _scan_target = target
        print(f"[*] Remote scan: {target} (SAST={run_sast}, Trivy={run_trivy})")
        results = []

        try:
            if run_sast:
                results.extend(run_sast_scan(target))
            if run_trivy:
                results.extend(run_trivy_scan(target))
            if not run_sast and not run_trivy:
                active_hosts = [target]
                if nmap_mode != "aucun":
                    try:
                        cmd = ["nmap", "-sn", target]
                        if nmap_mode == "agressif":
                            cmd = ["nmap", "-O", "-sV", target]
                        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                        active_hosts = []
                        for line in res.stdout.splitlines():
                            if "Nmap scan report for" in line:
                                active_hosts.append(line.split()[-1].strip("()"))
                        if not active_hosts:
                            active_hosts = [target]
                    except Exception as e:
                        print(f"[!] Nmap error: {e}")
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
                                            try: results.append(json.loads(line))
                                            except: pass
                                os.remove("/tmp/nuclei_out.json")
                    except Exception as e:
                        print(f"[!] Nuclei error: {e}")
        finally:
            _scanning = False; _scan_target = ""

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
    print(f"[*] Sentient AI Scanner Agent on port {PORT}")
    if MASTER_URL:
        print(f"[*] Heartbeats → {MASTER_URL}")
        threading.Thread(target=send_heartbeat, daemon=True).start()
    with socketserver.TCPServer(("", PORT), ScannerAgentHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentient AI Scanner Agent")
    parser.add_argument("--master", default="", help="URL du serveur principal (ex: http://192.168.1.104:8501)")
    parser.add_argument("--name", default="", help="Nom de la sonde (ex: VPS Paris)")
    parser.add_argument("--port", type=int, default=8502, help="Port d'écoute (défaut: 8502)")
    parser.add_argument("--token", default="sentient_secure_token_2026", help="Token d'authentification")
    args = parser.parse_args()
    PORT = args.port
    TOKEN = args.token
    MASTER_URL = args.master
    AGENT_NAME = args.name
    run()
