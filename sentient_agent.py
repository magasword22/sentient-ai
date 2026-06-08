#!/usr/bin/env python3
import http.server
import socketserver
import json
import subprocess
import os
import urllib.parse

PORT = 8502
TOKEN = "sentient_secure_token_2026"

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
        
        if not target:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing target parameter")
            return
            
        print(f"[*] Running remote scan for target: {target}")
        
        # 1. Découverte d'hôtes Nmap
        active_hosts = [target]
        if nmap_mode != "aucun":
            try:
                cmd = ["nmap", "-sn", target]
                if nmap_mode == "aggressif":
                    cmd = ["nmap", "-O", "-sV", target]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                # Parse basic hosts (simplifié pour l'agent)
                active_hosts = []
                for line in res.stdout.splitlines():
                    if "Nmap scan report for" in line:
                        parts = line.split()
                        active_hosts.append(parts[-1].strip("()"))
                if not active_hosts:
                    active_hosts = [target]
            except Exception as e:
                print(f"[!] Error running Nmap: {e}")
                
        # 2. Nuclei Scan
        results = []
        if active_hosts:
            try:
                for host in active_hosts:
                    cmd = ["nuclei", "-target", host, "-json-export", "/tmp/nuclei_out.json"]
                    if nuclei_tags:
                        cmd.extend(["-tags", ",".join(nuclei_tags)])
                    # Run nuclei
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
                    # Charger les résultats
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
                print(f"[!] Error running Nuclei: {e}")
                
        # Renvoyer les résultats au format JSON
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(results).encode('utf-8'))

    def do_GET(self):
        # Health check
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
