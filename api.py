#!/usr/bin/env python3
"""
Sentient AI — API Backend (FastAPI)
Remplace Streamlit : endpoints REST + WebSocket + frontend SPA statique.
Lancement : uvicorn api:app --host 0.0.0.0 --port 8501
"""

import sys, os, json, uuid, threading, time, sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pydantic

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import (
    discover_active_hosts, scan_nuclei, analyze_with_ollama,
    run_sast_scan, run_trivy_scan, export_to_pdf, run_recon_pipeline
)
from database import init_db, add_scan, get_history, verify_user, add_user, delete_user, get_users
from database import add_schedule, get_schedules, delete_schedule, update_schedule_last_run
import report_config
import compliance
import roi_calculator
import rag
import alerts
import defectdojo
import autotune

# ── App ──────────────────────────────────────────────────────────────────
app = FastAPI(title="Sentient AI API", version="2.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://[::1]:8501",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

# ── Rate limiter (in-memory, 10 req/sec per IP) ──────────────────────────
_rate_store: dict = {}

@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    from time import time
    ip = request.client.host if request.client else "unknown"
    now = time()
    window = _rate_store.get(ip, [])
    window = [t for t in window if now - t < 1.0]
    if len(window) > 20:  # 20 req/sec max
        return JSONResponse({"detail": "Trop de requêtes"}, status_code=429)
    window.append(now)
    _rate_store[ip] = window
    return await call_next(request)

# ── Security mode ────────────────────────────────────────────────────────
SECURITY_MODE = os.environ.get("SECURITY_MODE", "local")  # "local" | "public"
API_TOKEN = os.environ.get("API_TOKEN", "")  # Required when SECURITY_MODE=public

@app.middleware("http")
async def security_headers_middleware(request, call_next):
    """Ajoute les en-têtes de sécurité HTTP."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if SECURITY_MODE == "public":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:;"
    return response

@app.middleware("http")
async def api_auth_middleware(request, call_next):
    """En mode public, vérifie le token Bearer sur toutes les routes /api/ (sauf login)."""
    if SECURITY_MODE == "public" and request.url.path.startswith("/api/") and request.url.path != "/api/auth/login":
        auth = request.headers.get("Authorization", "")
        if not auth or auth != f"Bearer {API_TOKEN}":
            return JSONResponse({"detail": "Authentification requise — mode public activé"}, status_code=401)
    return await call_next(request)

# ── Scan state ───────────────────────────────────────────────────────────
active_scans: dict[str, dict] = {}  # scan_id → {status, progress, result}

# ── Pydantic models ──────────────────────────────────────────────────────
class LoginRequest(pydantic.BaseModel):
    username: str
    password: str

class ScanRequest(pydantic.BaseModel):
    target: str
    nmap_mode: str = "T4"
    nuclei_tags: Optional[list[str]] = None
    nuclei_mode: str = "full"
    use_sast: bool = False
    use_trivy: bool = False
    sast_path: str = "."
    trivy_target: str = ""
    use_agressive: bool = False
    use_vuln_script: bool = False
    evasion_fragment: bool = False
    evasion_decoy: str = ""
    evasion_mac: str = ""
    auth_cookies: str = ""
    use_subfinder: bool = False
    use_gobuster: bool = False
    report_lang: str = "Français"
    demo_mode: bool = False
    probe_url: str = ""  # URL de la sonde distante (ex: http://vps-ip:8502)

class ConfigUpdate(pydantic.BaseModel):
    company_name: Optional[str] = None
    footer_text: Optional[str] = None
    primary_color: Optional[str] = None
    logo_path: Optional[str] = None
    theme: Optional[str] = None
    sector: Optional[str] = None
    company_size: Optional[str] = None
    data_sensitivity: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    deepseek_api_key: Optional[str] = None
    mistral_api_key: Optional[str] = None
    webhook_provider: Optional[str] = None
    webhook_url: Optional[str] = None

# ── Auth ─────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def login(req: LoginRequest):
    if verify_user(req.username, req.password):
        return {"status": "ok", "username": req.username, "role": req.username}
    raise HTTPException(401, "Identifiants invalides")

# ── Config ───────────────────────────────────────────────────────────────
@app.get("/api/config")
def get_config():
    cfg = report_config.load_report_config()
    cfg["security_mode"] = SECURITY_MODE
    cfg["api_token"] = API_TOKEN[:4] + "****" if API_TOKEN else ""
    return cfg

@app.post("/api/config")
def update_config(cfg: ConfigUpdate):
    current = report_config.load_report_config()
    for k, v in cfg.model_dump(exclude_none=True).items():
        current[k] = v
    report_config.save_report_config(**current)
    return {"status": "ok"}

# ── History ──────────────────────────────────────────────────────────────
@app.get("/api/history")
def history():
    return get_history()

# ── Reports ──────────────────────────────────────────────────────────────
@app.get("/api/reports")
def list_reports():
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob("*.pdf"), key=lambda f: f.stat().st_mtime, reverse=True)
    return [{"name": f.name, "size": f.stat().st_size, "date": datetime.fromtimestamp(f.stat().st_mtime).isoformat()} for f in files[:20]]

@app.get("/api/reports/{filename}")
def download_report(filename: str):
    # Block path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(400, "Nom de fichier invalide")
    path = Path("reports") / filename
    path = path.resolve()
    if not str(path).startswith(str(Path("reports").resolve())):
        raise HTTPException(403, "Accès refusé")
    if not path.exists():
        raise HTTPException(404, "Fichier introuvable")
    return FileResponse(path, media_type="application/pdf", filename=path.name)

# ── Telemetry ────────────────────────────────────────────────────────────
@app.get("/api/telemetry")
def telemetry():
    return autotune.get_telemetry()

# ── IP LAN ───────────────────────────────────────────────────────────────
@app.get("/api/ip")
def get_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return {"ip": ip}

# ── Benchmark IA ──────────────────────────────────────────────────────────
class BenchmarkRequest(pydantic.BaseModel):
    model: str
    prompt: str = "Explique-moi la théorie de la relativité générale en 3 phrases simples."

@app.post("/api/benchmark")
def run_benchmark(req: BenchmarkRequest):
    """Test de vitesse de l'IA locale (tokens/seconde)."""
    import time, requests
    start = time.time()
    try:
        ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        r = requests.post(f"{ollama_url}/api/generate", json={"model": req.model, "prompt": req.prompt, "stream": False}, timeout=120)
        elapsed = time.time() - start
        if r.status_code == 200:
            d = r.json()
            eval_count = d.get("eval_count", 0)
            eval_ns = d.get("eval_duration", 0)
            prompt_count = d.get("prompt_eval_count", 0)
            prompt_ns = d.get("prompt_eval_duration", 0)
            total_ns = d.get("total_duration", 0)
            tps = eval_count / (eval_ns / 1e9) if eval_ns > 0 else (eval_count / elapsed if elapsed > 0 else 0)
            prompt_tps = prompt_count / (prompt_ns / 1e9) if prompt_ns > 0 else 0
            return {
                "status": "ok", "model": req.model,
                "tokens_per_sec": round(tps, 2),
                "prompt_tokens_per_sec": round(prompt_tps, 2),
                "total_sec": round(total_ns / 1e9 if total_ns > 0 else elapsed, 2),
                "eval_count": eval_count,
                "response_text": d.get("response", "")[:500],
            }
        return {"status": "error", "message": f"Ollama returned {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ── RAG ──────────────────────────────────────────────────────────────────
@app.post("/api/rag/upload")
async def upload_rag(file: UploadFile):
    os.makedirs("rag_db", exist_ok=True)
    path = os.path.join("rag_db", file.filename)
    with open(path, "wb") as f:
        f.write(await file.read())
    rag.ingest_document(path)
    return {"status": "ok", "file": file.filename}

@app.get("/api/rag/documents")
def list_rag_docs():
    return rag.list_documents() if hasattr(rag, 'list_documents') else []

@app.post("/api/rag/activate")
def activate_standards():
    """Ingère les 4 standards de sécurité dans ChromaDB (ANSSI, CIS, OWASP, Kernel Exploits)."""
    standards_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "standards")
    files = ["anssi_guide.md", "cis_benchmarks.md", "owasp_top_10.md", "kernel_exploits.md"]
    count = 0
    for fname in files:
        path = os.path.join(standards_dir, fname)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    rag.add_document(f.read(), fname)
                count += 1
            except Exception:
                pass
    return {"status": "ok", "ingested": count, "total": len(files)}

# ── Schedule ─────────────────────────────────────────────────────────────
@app.get("/api/schedules")
def schedules():
    return get_schedules()

@app.post("/api/schedules")
def add_schedule_endpoint(target: str, frequency: str, nmap_mode: str, nuclei_tags: str = "", report_lang: str = "Français"):
    add_schedule(target, frequency, nmap_mode, nuclei_tags, report_lang)
    return {"status": "ok"}

@app.delete("/api/schedules/{sid}")
def delete_schedule_endpoint(sid: int):
    delete_schedule(sid)
    return {"status": "ok"}

# ── Scan (REST) ──────────────────────────────────────────────────────────
@app.post("/api/scan")
def start_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    active_scans[scan_id] = {"status": "starting", "progress": 0, "steps": [], "result": None, "logs": []}

    def run():
        import io
        log_buffer = io.StringIO()
        import builtins as _b
        _original_print = _b.print
        def _capture_print(*args, **kwargs):
            msg = " ".join(str(a) for a in args)
            log_buffer.write(msg + "\n")
            active_scans[scan_id]["logs"].append(msg)
            _original_print(*args, **kwargs)
        _b.print = _capture_print

        try:
            state = active_scans[scan_id]
            state["status"] = "running"
            state["logs"].append("🚀 Démarrage de l'audit...")

            # Step 1: Discovery
            state["steps"].append({"name": "Découverte réseau", "status": "running"})
            state["progress"] = 10

            if req.demo_mode:
                time.sleep(0.5)
                hosts = ["demo-target.local"]
                state["steps"][-1]["status"] = "done"
                state["steps"][-1]["detail"] = "Cible de démo détectée"

                state["steps"].append({"name": "Scan vulnérabilités", "status": "running"})
                state["progress"] = 30
                time.sleep(0.5)
                vulns = [
                    {"template-id": "tomcat-default-login", "info": {"name": "Tomcat Default Credentials", "severity": "critical", "description": "Admin panel uses admin:admin"}, "host": "http://demo-target.local:8080", "matched-at": "http://demo-target.local:8080/manager/html"},
                    {"template-id": "git-exposure", "info": {"name": "Git Config Exposure", "severity": "high", "description": ".git/config is publicly exposed"}, "host": "http://demo-target.local", "matched-at": "http://demo-target.local/.git/config"},
                ]
                state["steps"][-1]["status"] = "done"
                state["steps"][-1]["detail"] = f"{len(vulns)} failles (simulées)"
            else:
                # ── Remote probe ──────────────────────────────────────────
                if req.probe_url:
                    state["steps"].append({"name": "Scan distant via sonde", "status": "running"})
                    try:
                        import requests as http_req
                        # Get probe auth token from config
                        probes = report_config.load_report_config().get("remote_probes", [])
                        token = ""
                        for p in probes:
                            if p.get("url", "") == req.probe_url:
                                token = p.get("token", "")
                                break
                        resp = http_req.post(
                            req.probe_url,
                            json={
                                "target": req.target,
                                "nmap_mode": "agressif" if req.use_agressive else ("full" if req.nmap_mode == "Full" else "standard"),
                                "nuclei_tags": req.nuclei_tags,
                                "sast": req.use_sast,
                                "trivy": req.use_trivy,
                            },
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=300
                        )
                        if resp.status_code == 200:
                            vulns = resp.json()
                            hosts = list(set([v.get("host", req.target) for v in vulns])) or [req.target]
                            state["steps"][-1]["status"] = "done"
                            state["steps"][-1]["detail"] = f"{len(vulns)} failles via sonde"
                        else:
                            state["steps"][-1]["status"] = "done"
                            state["steps"][-1]["detail"] = f"Erreur sonde: {resp.status_code}"
                            vulns = []
                            hosts = [req.target]
                    except Exception as e:
                        state["steps"][-1]["status"] = "done"
                        state["steps"][-1]["detail"] = f"Sonde injoignable: {e}"
                        vulns = []
                        hosts = [req.target]
                    state["progress"] = 55

                # ── Local scan ────────────────────────────────────────────
                else:
                    # Recon
                    if req.use_subfinder or req.use_gobuster:
                        recon = run_recon_pipeline(req.target, run_subfinder=req.use_subfinder, run_gobuster=req.use_gobuster)

                    # Evasion opts
                    ev_opts = {
                        "fragment": req.evasion_fragment,
                        "decoy": req.evasion_decoy or None,
                        "spoof_mac": req.evasion_mac or None,
                    }
                    hosts = discover_active_hosts(
                        req.target, req.nmap_mode,
                        use_agressive=req.use_agressive,
                        use_vuln_script=req.use_vuln_script,
                        evasion_options=ev_opts
                    )
                    if not hosts:
                        state["status"] = "error"
                        state["error"] = "Aucun hôte actif détecté"
                        active_scans[scan_id] = state
                        return
                    state["steps"][-1]["status"] = "done"
                    state["steps"][-1]["detail"] = f"{len(hosts)} hôte(s)"
                    state["progress"] = 30

                    # Step 2: Nuclei
                    state["steps"].append({"name": "Scan vulnérabilités", "status": "running"})
                    tags = req.nuclei_tags or None
                    vulns = scan_nuclei(hosts, selected_tags=tags)
                    state["steps"][-1]["status"] = "done"
                    state["steps"][-1]["detail"] = f"{len(vulns)} failles"
                    state["progress"] = 55

            # SAST
            if req.use_sast:
                state["steps"].append({"name": "SAST (code source)", "status": "running"})
                vulns += run_sast_scan(req.sast_path)
                state["steps"][-1]["status"] = "done"
                state["progress"] = 65

            # Trivy
            if req.use_trivy and req.trivy_target:
                state["steps"].append({"name": "Trivy (conteneurs)", "status": "running"})
                vulns += run_trivy_scan(req.trivy_target)
                state["steps"][-1]["status"] = "done"
                state["progress"] = 75

            # Step 3: AI Analysis
            state["steps"].append({"name": "Analyse IA (Ollama)", "status": "running"})
            state["progress"] = 80
            target_desc = f"{req.target} ({len(hosts)} hôte(s))"
            report_md = analyze_with_ollama(target_desc, vulns, language=req.report_lang)
            state["steps"][-1]["status"] = "done"
            state["progress"] = 95

            # Step 4: Export
            state["steps"].append({"name": "Export PDF", "status": "running"})
            os.makedirs("reports", exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"reports/audit_{ts}.pdf"
            md_filename = f"reports/audit_{ts}.md"
            with open(md_filename, "w") as f:
                f.write(report_md)
            export_to_pdf(report_md, pdf_filename)
            state["steps"][-1]["status"] = "done"
            state["steps"][-1]["detail"] = pdf_filename

            # Save
            add_scan(req.target, len(hosts), len(vulns), pdf_filename)
            state["status"] = "done"
            state["progress"] = 100
            state["result"] = {
                "hosts": len(hosts),
                "vulns": len(vulns),
                "report_pdf": pdf_filename,
                "report_md": md_filename,
                "vuln_list": vulns[:50],
            }
            active_scans[scan_id] = state

        except Exception as e:
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

    threading.Thread(target=run, daemon=True).start()
    return {"scan_id": scan_id, "status": "starting"}

@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan introuvable")
    return active_scans[scan_id]

# ── WebSocket for live progress ──────────────────────────────────────────
@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: str):
    if SECURITY_MODE == "public":
        # Vérifier le token dans les query params WS (le header Authorization n'est pas supporté par WebSocket)
        token = ws.query_params.get("token", "")
        if token != API_TOKEN:
            await ws.close(code=4001, reason="Authentification requise")
            return
    await ws.accept()
    last_progress = -1
    while True:
        try:
            state = active_scans.get(scan_id, {})
            if state.get("progress") != last_progress or state.get("status") in ("done", "error"):
                await ws.send_json({
                    "progress": state.get("progress", 0),
                    "status": state.get("status", "unknown"),
                    "steps": state.get("steps", []),
                    "result": state.get("result"),
                    "error": state.get("error"),
                    "logs": state.get("logs", [])[-20:],  # 20 dernières lignes
                })
                last_progress = state.get("progress", 0)
                if state.get("status") in ("done", "error"):
                    break
            await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            break

import asyncio

# ── Probes management ─────────────────────────────────────────────────────
@app.post("/api/probes")
def add_probe(name: str, url: str, token: str = "CHANGE_ME"):
    cfg = report_config.load_report_config()
    probes = cfg.get("remote_probes", [])
    probes.append({"name": name, "url": url, "token": token})
    cfg["remote_probes"] = probes
    report_config.save_report_config(**cfg)
    return {"status": "ok"}

@app.delete("/api/probes/{name}")
def delete_probe(name: str):
    cfg = report_config.load_report_config()
    cfg["remote_probes"] = [p for p in cfg.get("remote_probes", []) if p.get("name") != name]
    report_config.save_report_config(**cfg)
    return {"status": "ok"}

# ── Probe monitoring ──────────────────────────────────────────────────────
# In-memory state: {probe_name: {last_seen, ip, status, uptime, active_scan}}
probe_health: dict = {}

@app.post("/api/probes/heartbeat")
def probe_heartbeat(name: str = "", url: str = "", scan_active: bool = False, scan_target: str = ""):
    """Les sondes envoient un heartbeat toutes les 30s pour signaler qu'elles sont en ligne."""
    now = datetime.now().isoformat()
    probe_health[name or url] = {
        "name": name or url,
        "url": url,
        "last_seen": now,
        "status": "online",
        "active_scan": scan_active,
        "scan_target": scan_target if scan_active else "",
        "first_seen": probe_health.get(name or url, {}).get("first_seen", now),
    }
    return {"status": "ok"}

@app.get("/api/probes/status")
def probe_status():
    """Retourne l'état de toutes les sondes enregistrées + health."""
    cfg = report_config.load_report_config()
    probes = cfg.get("remote_probes", [])
    now = datetime.now()
    result = []
    for p in probes:
        h = probe_health.get(p["name"], {})
        last_seen = h.get("last_seen", "")
        is_online = False
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen)
                is_online = (now - last_dt).total_seconds() < 120  # 2 min timeout
            except:
                pass
        result.append({
            "name": p["name"],
            "url": p["url"],
            "online": is_online,
            "last_seen": last_seen,
            "active_scan": h.get("active_scan", False),
            "scan_target": h.get("scan_target", ""),
            "first_seen": h.get("first_seen", ""),
        })
    return result

# ── Users ────────────────────────────────────────────────────────────────
@app.get("/api/users")
def list_users():
    return get_users()

@app.post("/api/users")
def create_user(username: str, password: str):
    add_user(username, password)
    return {"status": "ok"}

@app.delete("/api/users/{username}")
def remove_user(username: str):
    delete_user(username)
    return {"status": "ok"}

# ── Compliance ───────────────────────────────────────────────────────────
@app.get("/api/compliance")
def get_compliance():
    cfg = report_config.load_report_config()
    return compliance.get_compliance_matrix(cfg.get("sector", ""), cfg.get("company_size", ""))

# ── ROI ──────────────────────────────────────────────────────────────────
@app.get("/api/roi")
def get_roi():
    cfg = report_config.load_report_config()
    return roi_calculator.calculate_financial_risk(
        vulns=[],
        sector=cfg.get("sector", "Finance"),
        company_size=cfg.get("company_size", "PME"),
        data_sensitivity=cfg.get("data_sensitivity", "PII"),
        custom_breach_costs=cfg.get("custom_breach_costs"),
        custom_remediation_costs=cfg.get("custom_remediation_costs"),
    )

# ── Serve frontend SPA ───────────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

# Serve assets from project root (logo, etc.)
assets_dir = os.path.dirname(os.path.abspath(__file__))

@app.get("/assets/{path:path}")
async def serve_assets(path: str):
    """Sert les fichiers du dossier assets/."""
    if ".." in path or path.startswith("/"):
        raise HTTPException(400, "Chemin invalide")
    file_path = os.path.join(assets_dir, "assets", path)
    file_path = os.path.realpath(file_path)
    if not file_path.startswith(os.path.realpath(os.path.join(assets_dir, "assets"))):
        raise HTTPException(403, "Accès refusé")
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    raise HTTPException(404)

# ── PrivEsc endpoint ─────────────────────────────────────────────────────
class PrivEscRequest(pydantic.BaseModel):
    host: str
    port: int = 22
    username: str
    password: str = ""
    key_path: str = ""

@app.post("/api/privesc")
def run_privesc(req: PrivEscRequest):
    """Lance un audit système LPE via SSH."""
    try:
        from host_auditor import run_remote_privesc_audit
        result = run_remote_privesc_audit(req.host, req.username, req.password, req.key_path, req.port)
        return {"status": "ok", "result": result}
    except Exception as e:
        raise HTTPException(500, str(e))

# ── PoC generation endpoint ──────────────────────────────────────────────
class PoCRequest(pydantic.BaseModel):
    cve_id: str

@app.post("/api/poc")
def generate_poc(req: PoCRequest):
    """Génère un guide de détection pour une CVE."""
    try:
        from agents import run_poc_generation_crew
        result = run_poc_generation_crew(req.cve_id)
        return {"status": "ok", "result": result}
    except Exception as e:
        raise HTTPException(500, str(e))

# ── Chat endpoint ─────────────────────────────────────────────────────────
class ChatRequest(pydantic.BaseModel):
    query: str
    history: list[dict] = []
    report_md: str = ""
    use_web: bool = False

@app.post("/api/chat")
def chat(req: ChatRequest):
    """Assistant virtuel RAG."""
    try:
        from chat import stream_chat_response
        response = stream_chat_response(req.report_md, req.history, req.query, req.use_web)
        # stream_chat_response returns a generator — join tokens, handling both str and LangChain chunks
        tokens = []
        for chunk in response:
            if hasattr(chunk, 'content'):
                tokens.append(chunk.content)
            elif isinstance(chunk, str):
                tokens.append(chunk)
            else:
                tokens.append(str(chunk))
        response = ''.join(tokens)
        return {"status": "ok", "response": response}
    except Exception as e:
        raise HTTPException(500, str(e))

# ── Serve frontend SPA (fallback) ─────────────────────────────────────────

@app.get("/")
@app.get("/{path:path}")
async def serve_spa(path: str = ""):
    """Sert le frontend SPA. Toutes les routes non-API renvoient index.html."""
    if path.startswith("api/") or path.startswith("ws/"):
        raise HTTPException(404)
    file_path = os.path.join(static_dir, path) if path else os.path.join(static_dir, "index.html")
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(static_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8501))
    ssl_cert = os.environ.get("SSL_CERT", "")   # Chemin vers fullchain.pem
    ssl_key = os.environ.get("SSL_KEY", "")      # Chemin vers privkey.pem
    ssl_kwargs = {}
    if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        ssl_kwargs = {"ssl_certfile": ssl_cert, "ssl_keyfile": ssl_key}
        print(f"[SECURITY] HTTPS activé avec {ssl_cert}")
    print(f"[SECURITY] Mode: {SECURITY_MODE} {'— token auth actif' if SECURITY_MODE == 'public' else '— pas d authentification API'}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", **ssl_kwargs)
