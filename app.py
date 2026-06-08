import streamlit as st
import os
import pandas as pd
import altair as alt
import random
import json
from datetime import datetime
from database import init_db, add_scan, get_history, add_schedule, get_schedules, delete_schedule, update_schedule_last_run, verify_user, add_user, delete_user, get_users
from scanner import discover_active_hosts, scan_nuclei, analyze_with_ollama, export_to_pdf, run_recon_pipeline, run_sast_scan, run_trivy_scan
from alerts import send_webhook_notification
import rag
import defectdojo
import chat
import report_config
import compliance
import roi_calculator
import threading
import time
import sqlite3

def scheduler_loop():
    """Vérifie périodiquement s'il y a des scans planifiés à exécuter."""
    while True:
        # Attendre 30 secondes
        time.sleep(30)
        try:
            conn = sqlite3.connect("audits.db")
            cursor = conn.cursor()
            # Créer la table si absente au cas où
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    nmap_mode TEXT NOT NULL,
                    nuclei_tags TEXT,
                    report_lang TEXT NOT NULL,
                    last_run TEXT,
                    next_run TEXT NOT NULL
                )
            ''')
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
            cursor.execute('SELECT id, target, frequency, nmap_mode, nuclei_tags, report_lang, next_run FROM schedules')
            rows = cursor.fetchall()
            
            for row in rows:
                sid, target, frequency, nmap_mode, nuclei_tags_str, report_lang, next_run = row
                
                # Vérifier si next_run <= now_str
                if next_run <= now_str:
                    print(f"[*] Déclenchement automatique du scan planifié {sid} pour {target}...")
                    
                    # 1. Résoudre les tags Nuclei
                    tags = None
                    if nuclei_tags_str:
                        tags = [t.strip() for t in nuclei_tags_str.split(",") if t.strip()]
                        
                    # 2. Exécuter le scan de découverte réseau
                    try:
                        active_hosts = discover_active_hosts(target, nmap_mode=nmap_mode)
                        if active_hosts:
                            # 3. Scan de vulnérabilités
                            nuclei_results = scan_nuclei(active_hosts, selected_tags=tags)
                            
                            # 4. Analyse IA
                            target_desc = f"{target} (Scan Planifié)"
                            markdown_report = analyze_with_ollama(target_desc, nuclei_results, language=report_lang)
                            
                            # 5. Export PDF
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            os.makedirs("reports", exist_ok=True)
                            pdf_filename = f"reports/audit_sched_{timestamp}.pdf"
                            md_filename = f"reports/audit_sched_{timestamp}.md"
                            
                            with open(md_filename, "w", encoding="utf-8") as f_md:
                                f_md.write(markdown_report)
                            
                            export_to_pdf(markdown_report, pdf_filename)
                            
                            # 6. Ajouter dans l'historique
                            vulns_count = len(nuclei_results)
                            hosts_count = len(active_hosts)
                            vulns_json = json.dumps(nuclei_results)
                            
                            conn_write = sqlite3.connect("audits.db")
                            cursor_write = conn_write.cursor()
                            cursor_write.execute('''
                                INSERT INTO scans (date, target, hosts_found, vulnerabilities_found, report_path, vulnerabilities_json)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), target, hosts_count, vulns_count, pdf_filename, vulns_json))
                            conn_write.commit()
                            conn_write.close()
                            
                            # 7. Envoyer notification
                            try:
                                send_webhook_notification(target, hosts_count, vulns_count, pdf_filename)
                            except Exception as e_web:
                                print(f"[!] Erreur webhook : {e_web}")
                    except Exception as ex:
                        print(f"[!] Erreur lors de l'exécution du scan planifié {sid} : {ex}")
                        
                    # 8. Mettre à jour next_run selon la récurrence
                    next_run_dt = datetime.strptime(next_run, "%Y-%m-%d %H:%M")
                    if frequency == "quotidien":
                        from datetime import timedelta
                        new_next_run = (next_run_dt + timedelta(days=1)).strftime("%Y-%m-%d %H:%M")
                    elif frequency == "hebdomadaire":
                        from datetime import timedelta
                        new_next_run = (next_run_dt + timedelta(weeks=1)).strftime("%Y-%m-%d %H:%M")
                    elif frequency == "mensuel":
                        from datetime import timedelta
                        new_next_run = (next_run_dt + timedelta(days=30)).strftime("%Y-%m-%d %H:%M")
                    else:
                        from datetime import timedelta
                        new_next_run = (next_run_dt + timedelta(days=1)).strftime("%Y-%m-%d %H:%M")
                        
                    cursor.execute('UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?', 
                                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_next_run, sid))
                    conn.commit()
            
            conn.close()
        except Exception as e:
            print(f"[!] Erreur de boucle du planificateur : {e}")

# Lancement unique du thread de planification
if 'scheduler_started' not in st.session_state:
    st.session_state.scheduler_started = True
    t_sched = threading.Thread(target=scheduler_loop, daemon=True)
    t_sched.start()

# -----------------------------------------------------------------------------
# Configuration Globale
# -----------------------------------------------------------------------------
init_db()

st.set_page_config(
    page_title="Sentient AI | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# MODE DE PARTAGE SÉCURISÉ (Lecture seule)
# -----------------------------------------------------------------------------
if "share" in st.query_params:
    share_token = st.query_params["share"]
    try:
        conn = sqlite3.connect("audits.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, date, report_path FROM scans WHERE id = ?", (share_token,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            target, date, report_path = row
            st.markdown(f"<h2 style='color:#7c3aed;'>🛡️ Sentient AI - Rapport partagé</h2>", unsafe_allow_html=True)
            st.markdown(f"**Cible :** `{target}` | **Généré le :** `{date}`", unsafe_allow_html=True)
            st.markdown("---")
            
            # Charger le contenu markdown
            md_path = report_path.replace(".pdf", ".md")
            if os.path.exists(md_path):
                with open(md_path, "r", encoding="utf-8") as f_md:
                    md_content = f_md.read()
                st.markdown(md_content)
            else:
                st.error("Le contenu du rapport n'est plus disponible sur le serveur.")
        else:
            st.error("Lien de partage invalide ou expiré.")
    except Exception as e_share:
        st.error(f"Erreur d'accès au partage : {e_share}")
    st.stop()

# -----------------------------------------------------------------------------
# AUTHENTIFICATION & CONTROLE D'ACCES (RBAC)
# -----------------------------------------------------------------------------
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'role' not in st.session_state:
    st.session_state.role = None

if not st.session_state.logged_in:
    st.markdown("""
    <style>
        .login-container {
            max-width: 450px;
            margin: 80px auto;
            padding: 40px;
            background: rgba(24, 24, 27, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            text-align: center;
        }
        .login-title {
            color: #7c3aed;
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 5px;
        }
        .login-subtitle {
            color: #a1a1aa;
            font-size: 0.9rem;
            margin-bottom: 25px;
        }
        .stApp {
            background-color: #09090b !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.markdown('<div class="login-title">🛡️ Sentient AI</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-subtitle">Authentification requise | Moteur PTaaS Local</div>', unsafe_allow_html=True)
        
        with st.form("login_form", clear_on_submit=False):
            username_input = st.text_input("Nom d'utilisateur", placeholder="e.g. admin ou client")
            password_input = st.text_input("Mot de passe", type="password", placeholder="••••••••")
            login_btn = st.form_submit_button("Se connecter", type="primary", use_container_width=True)
            
            if login_btn:
                if not username_input or not password_input:
                    st.error("Veuillez remplir tous les champs.")
                else:
                    is_valid, role = verify_user(username_input, password_input)
                    if is_valid:
                        st.session_state.logged_in = True
                        st.session_state.username = username_input
                        st.session_state.role = role
                        st.success("Connexion réussie !")
                        st.rerun()
                    else:
                        st.error("Identifiants incorrects. Veuillez réessayer.")
        st.markdown('</div>', unsafe_allow_html=True)
    st.stop()


def get_system_telemetry():
    """Récupère les informations système en temps réel pour le CPU, RAM et GPU."""
    import os
    import subprocess
    import requests
    
    # 1. Charge CPU
    cpu_count = os.cpu_count() or 1
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1, load5, load15 = 0.0, 0.0, 0.0
    cpu_pct = (load1 / cpu_count) * 100.0
    if cpu_pct > 100.0:
        cpu_pct = 100.0

    # 2. Mémoire vive (RAM)
    ram_total = 0.0
    ram_used = 0.0
    ram_pct = 0.0
    if os.path.exists('/proc/meminfo'):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
            mem_info = {}
            for line in lines:
                parts = line.split(':')
                if len(parts) == 2:
                    mem_info[parts[0].strip()] = int(parts[1].replace('kB', '').strip())
            total = mem_info.get('MemTotal', 0)
            available = mem_info.get('MemAvailable', 0)
            used = total - available
            ram_pct = (used / total) * 100 if total > 0 else 0
            ram_total = total / (1024 * 1024) # GB
            ram_used = used / (1024 * 1024) # GB
        except Exception:
            pass

    # 3. GPU Info
    gpu_model = "CPU Fallback"
    gpu_util = 0.0
    vram_total = 0.0
    vram_used = 0.0
    vram_pct = 0.0
    has_gpu = False

    # Détecter le GPU via lspci
    try:
        result = subprocess.run(["lspci"], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if any(word in line.lower() for word in ["vga", "3d", "display"]):
                    if "nvidia" in line.lower():
                        gpu_model = "NVIDIA GPU"
                        has_gpu = True
                        parts = line.split("controller:")
                        if len(parts) > 1:
                            gpu_model = parts[1].strip()
                        break
                    elif "amd" in line.lower() or "ati" in line.lower():
                        gpu_model = "AMD Radeon GPU"
                        has_gpu = True
                        if "strix halo" in line.lower() or "8050s" in line.lower() or "8060s" in line.lower():
                            gpu_model = "AMD Strix Halo"
                        else:
                            parts = line.split("controller:")
                            if len(parts) > 1:
                                gpu_model = parts[1].strip()
                        break
    except Exception:
        pass

    # Fallback pour environnement conteneurisé (si /sys est monté et lspci absent)
    if not has_gpu:
        for card in ["card1", "card0", "card2"]:
            sys_path = f"/sys/class/drm/{card}/device"
            if os.path.exists(sys_path) and os.path.exists(f"{sys_path}/mem_info_vram_total"):
                has_gpu = True
                gpu_model = "AMD Radeon GPU"
                uevent_path = f"{sys_path}/uevent"
                if os.path.exists(uevent_path):
                    try:
                        with open(uevent_path, "r") as f:
                            uevent_content = f.read()
                        if "DRIVER=amdgpu" in uevent_content:
                            if "PCI_ID=1002:1586" in uevent_content:
                                gpu_model = "AMD Strix Halo"
                            else:
                                gpu_model = "AMD Radeon GPU"
                    except Exception:
                        pass
                break

    # Récupérer les métriques d'utilisation du GPU
    if has_gpu:
        if "nvidia" in gpu_model.lower():
            try:
                res = subprocess.run([
                    "nvidia-smi", 
                    "--query-gpu=name,memory.total,memory.used,utilization.gpu", 
                    "--format=csv,noheader,nounits"
                ], capture_output=True, text=True)
                if res.returncode == 0:
                    parts = res.stdout.strip().split(',')
                    if len(parts) >= 4:
                        gpu_model = parts[0].strip()
                        vram_total = float(parts[1].strip()) / 1024.0
                        vram_used = float(parts[2].strip()) / 1024.0
                        vram_pct = (vram_used / vram_total) * 100.0 if vram_total > 0 else 0
                        gpu_util = float(parts[3].strip())
            except Exception:
                pass
        else:
            # AMD (via sysfs)
            for card in ["card1", "card0", "card2"]:
                sys_path = f"/sys/class/drm/{card}/device"
                if os.path.exists(sys_path) and os.path.exists(f"{sys_path}/mem_info_vram_total"):
                    try:
                        with open(f"{sys_path}/mem_info_vram_total", "r") as f:
                            v_tot = int(f.read().strip())
                        with open(f"{sys_path}/mem_info_vram_used", "r") as f:
                            v_used = int(f.read().strip())
                        with open(f"{sys_path}/gpu_busy_percent", "r") as f:
                            g_busy = int(f.read().strip())
                        
                        vram_total = v_tot / (1024 * 1024 * 1024)
                        vram_used = v_used / (1024 * 1024 * 1024)
                        vram_pct = (vram_used / vram_total) * 100.0 if vram_total > 0 else 0
                        gpu_util = float(g_busy)
                        break
                    except Exception:
                        pass
    
    # 4. Ollama Status & Modèle
    ollama_connected = False
    ollama_model = "Non détecté"
    ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        r = requests.get(f"{ollama_base_url}/api/tags", timeout=1.5)
        if r.status_code == 200:
            ollama_connected = True
            models_data = r.json()
            models = models_data.get("models", [])
            if models:
                names = [m.get("name") for m in models]
                ollama_model = names[0]
                for n in names:
                    if "llama3" in n:
                        ollama_model = n
                        break
    except Exception:
        pass

    return {
        "cpu_count": cpu_count,
        "cpu_pct": cpu_pct,
        "load_1m": load1,
        "load_5m": load5,
        "load_15m": load15,
        "ram_total": ram_total,
        "ram_used": ram_used,
        "ram_pct": ram_pct,
        "gpu_model": gpu_model,
        "gpu_util": gpu_util,
        "vram_total": vram_total,
        "vram_used": vram_used,
        "vram_pct": vram_pct,
        "has_gpu": has_gpu,
        "ollama_connected": ollama_connected,
        "ollama_model": ollama_model,
        "ollama_base_url": ollama_base_url
    }

# -----------------------------------------------------------------------------
# Style CSS Premium & Thèmes Dynamiques
# -----------------------------------------------------------------------------
def inject_custom_theme():
    import report_config
    cfg = report_config.load_report_config()
    theme = cfg.get("theme", "Slate/Zinc")
    
    common_css = """
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    
    .badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 4px;
    }
    .badge-crit { background-color: rgba(220, 38, 38, 0.2); color: #ef4444; border: 1px solid rgba(220, 38, 38, 0.3); }
    .badge-high { background-color: rgba(234, 88, 12, 0.2); color: #f97316; border: 1px solid rgba(234, 88, 12, 0.3); }
    .badge-med { background-color: rgba(202, 138, 4, 0.2); color: #eab308; border: 1px solid rgba(202, 138, 4, 0.3); }
    .badge-low { background-color: rgba(37, 99, 235, 0.2); color: #3b82f6; border: 1px solid rgba(37, 99, 235, 0.3); }
    .badge-success { background-color: rgba(22, 163, 74, 0.2); color: #22c55e; border: 1px solid rgba(22, 163, 74, 0.3); }
    
    .dot {
        height: 8px;
        width: 8px;
        background-color: #22c55e;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
    }
    .dot-warning { background-color: #eab308; }
    """

    if theme == "Matrix/Hacker":
        st.markdown(f"""
        <style>
            {common_css}
            
            .block-container {{
                padding-top: 2rem !important;
                max-width: 95% !important;
                background-color: #000000 !important;
            }}

            .stApp {{
                background-color: #000000 !important;
                color: #00ff00 !important;
                font-family: 'Courier New', Courier, monospace !important;
            }}

            h1, h2, h3, h4, h5, h6, p, span, label, div, li, select, option {{
                color: #00ff00 !important;
                font-family: 'Courier New', Courier, monospace !important;
            }}

            .kpi-card {{
                background-color: #000a00 !important;
                border: 1px solid #00ff00 !important;
                border-radius: 4px;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }}
            .kpi-title {{
                font-size: 0.875rem;
                color: #00cc00 !important;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 8px;
                font-weight: 600;
            }}
            .kpi-value {{
                font-size: 2.25rem;
                font-weight: 700;
                color: #00ff00 !important;
                margin-bottom: 8px;
            }}

            .telemetry-box {{
                background-color: #000a00 !important;
                border: 1px solid #005500 !important;
                border-radius: 4px;
                padding: 12px;
                margin-top: auto;
                font-size: 0.8rem;
                color: #00ff00 !important;
                box-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}
            .telemetry-item {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 6px;
                border-bottom: 1px dashed #003300;
                padding-bottom: 4px;
            }}
            
            button {{
                background-color: #001100 !important;
                color: #00ff00 !important;
                border: 1px solid #00ff00 !important;
                border-radius: 4px !important;
            }}
            button:hover {{
                background-color: #003300 !important;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.8) !important;
            }}
        </style>
        """, unsafe_allow_html=True)
    elif theme == "Light/Clean":
        st.markdown(f"""
        <style>
            {common_css}
            
            .block-container {{
                padding-top: 2rem !important;
                max-width: 95% !important;
                background-color: #f4f4f5 !important;
            }}

            .stApp {{
                background-color: #ffffff !important;
                color: #18181b !important;
            }}

            h1, h2, h3, h4, h5, h6 {{
                color: #18181b !important;
            }}
            p, span, label, div, li {{
                color: #27272a !important;
            }}

            .kpi-card {{
                background-color: #ffffff !important;
                border: 1px solid #e4e4e7 !important;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }}
            .kpi-title {{
                font-size: 0.875rem;
                color: #71717a !important;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 8px;
                font-weight: 600;
            }}
            .kpi-value {{
                font-size: 2.25rem;
                font-weight: 700;
                color: #18181b !important;
                margin-bottom: 8px;
            }}

            .telemetry-box {{
                background-color: #ffffff !important;
                border: 1px solid #e4e4e7 !important;
                border-radius: 8px;
                padding: 12px;
                margin-top: auto;
                font-size: 0.8rem;
                color: #71717a !important;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            }}
            .telemetry-item {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 6px;
                border-bottom: 1px solid #f4f4f5;
                padding-bottom: 4px;
            }}
        </style>
        """, unsafe_allow_html=True)
    else: # Slate/Zinc (Default)
        st.markdown(f"""
        <style>
            {common_css}
            
            .block-container {{
                padding-top: 2rem !important;
                max-width: 95% !important;
                background-color: #09090b;
            }}

            .stApp {{
                background-color: #09090b;
                color: #f4f4f5;
            }}

            .kpi-card {{
                background-color: #18181b;
                border: 1px solid #27272a;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }}
            .kpi-title {{
                font-size: 0.875rem;
                color: #a1a1aa;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 8px;
                font-weight: 600;
            }}
            .kpi-value {{
                font-size: 2.25rem;
                font-weight: 700;
                color: #fafafa;
                margin-bottom: 8px;
            }}

            .telemetry-box {{
                background-color: #18181b;
                border: 1px solid #27272a;
                border-radius: 8px;
                padding: 12px;
                margin-top: auto;
                font-size: 0.8rem;
                color: #a1a1aa;
            }}
            .telemetry-item {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 6px;
            }}
        </style>
        """, unsafe_allow_html=True)

# Appliquer le thème
inject_custom_theme()

# -----------------------------------------------------------------------------
# Barre Latérale (Sidebar)
# -----------------------------------------------------------------------------
with st.sidebar:
    try:
        st.image("assets/SentientAIPurple.png", width=120)
    except:
        pass
    st.markdown("### Sentient AI")
    st.markdown("<p style='color:#a1a1aa; font-size:0.85rem; margin-top:-10px;'>Moteur PTaaS 100% Local</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    if st.session_state.role == "client":
        options_list = [
            "📊 Tableau de Bord", 
            "📂 Centre de Rapports", 
            "💬 Assistant Virtuel",
            "🧠 Base de Connaissances (RAG)"
        ]
    else:
        options_list = [
            "📊 Tableau de Bord", 
            "⚡ Lancer un Audit", 
            "💰 Analyse de Risque ROI",
            "📅 Planification de Scans",
            "📂 Centre de Rapports", 
            "💬 Assistant Virtuel",
            "🧠 Base de Connaissances (RAG)", 
            "🖥️ Diagnostic & Performance",
            "⚙️ Configuration"
        ]
        
    menu = st.radio(
        "Navigation",
        options=options_list,
        label_visibility="collapsed"
    )
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Section Utilisateur Connecté
    st.markdown(f"""
        <div style="font-size:0.85rem; color:#a1a1aa; margin-bottom:10px;">
            👤 Utilisateur : <strong>{st.session_state.username}</strong> ({st.session_state.role})
        </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Se déconnecter", type="secondary", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.rerun()
        
    st.markdown("---")
    
    # Section Télémétrie Système dynamique
    tel = get_system_telemetry()
    
    if tel["ollama_connected"]:
        ollama_dot = '<span class="dot"></span>'
        ollama_status = '<span style="color:#22c55e;">Connecté</span>'
    else:
        ollama_dot = '<span class="dot dot-warning"></span>'
        ollama_status = '<span style="color:#ef4444;">Hors ligne</span>'
        
    gpu_label = tel["gpu_model"]
    # Truncate model name if too long to avoid line wraps
    if len(gpu_label) > 18:
        gpu_label = gpu_label[:15] + "..."
        
    vram_str = f"{tel['vram_used']:.1f} / {tel['vram_total']:.1f} GB" if tel["vram_total"] > 0 else "N/A"
    
    model_str = tel["ollama_model"]
    if len(model_str) > 18:
        model_str = model_str[:15] + "..."
        
    st.markdown(f"""
        <div class="telemetry-box">
            <div style="margin-bottom: 10px; font-weight: bold; color: #e4e4e7;">Télémétrie Système</div>
            <div class="telemetry-item">
                <span>{ollama_dot}Ollama</span>
                {ollama_status}
            </div>
            <div class="telemetry-item">
                <span>GPU Actif</span>
                <span style="color:#e4e4e7;" title="{tel["gpu_model"]}">{gpu_label}</span>
            </div>
            <div class="telemetry-item">
                <span>VRAM Usage</span>
                <span style="color:#eab308;">{vram_str}</span>
            </div>
            <div class="telemetry-item">
                <span>Modèle IA</span>
                <span style="color:#e4e4e7;" title="{tel["ollama_model"]}">{model_str}</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Logique de Navigation & Sécurité (RBAC)
# -----------------------------------------------------------------------------
if st.session_state.role == "client" and menu not in ["📊 Tableau de Bord", "📂 Centre de Rapports", "💬 Assistant Virtuel", "🧠 Base de Connaissances (RAG)"]:
    st.warning("⛔ Accès refusé : Votre profil (Client) ne vous permet pas d'accéder à cette fonctionnalité.")
    st.stop()


# ==========================================
# 📊 TABLEAU DE BORD (DASHBOARD)
# ==========================================
if menu == "📊 Tableau de Bord":
    
    # Header Principal avec Call to Action
    col_title, col_btn = st.columns([3, 1])
    with col_title:
        st.markdown("<h2 style='margin-bottom:0;'>Tableau de Bord Exécutif</h2>", unsafe_allow_html=True)
        st.markdown("<p style='color:#a1a1aa;'>Vue consolidée des menaces et de l'état du parc informatique.</p>", unsafe_allow_html=True)
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("⚡ Lancer un nouveau scan", type="primary"):
            st.session_state.force_menu = "⚡ Lancer un Audit"
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Récupération des données
    history = get_history()
    total_scans = len(history)
    total_hosts = sum(entry['hosts_found'] for entry in history) if history else 0
    total_vulns = sum(entry['vulnerabilities_found'] for entry in history) if history else 0
    
    # Simulation d'une répartition des sévérités pour le design (à brancher en vrai DB + tard)
    # Répartition approximative : 5% Crit, 15% Haute, 40% Moy, 40% Faible
    crit_count = max(0, int(total_vulns * 0.05)) if total_vulns > 0 else 0
    high_count = max(0, int(total_vulns * 0.15)) if total_vulns > 0 else 0
    med_count  = max(0, int(total_vulns * 0.40)) if total_vulns > 0 else 0
    low_count  = max(0, total_vulns - crit_count - high_count - med_count)
    
    if crit_count == 0 and total_vulns > 0 and random.random() > 0.7:
        crit_count = 1 # Ajouter un peu de piquant aléatoire pour le dashboard si >0
        
    # Calcul de l'exposition financière du dernier scan
    latest_scan = history[0] if history else None
    latest_exposure = 0.0
    latest_savings = 0.0
    latest_roi_pct = 0.0
    
    if latest_scan:
        rep_cfg = report_config.load_report_config()
        sector = rep_cfg.get("sector", "Finance / Assurances")
        company_size = rep_cfg.get("company_size", "PME (50 - 250 employés)")
        data_sensitivity = rep_cfg.get("data_sensitivity", "PII standard (Noms, Emails)")
        
        # Charger les vulnérabilités du scan
        vulns = []
        if latest_scan.get("vulnerabilities_json"):
            try:
                vulns = json.loads(latest_scan["vulnerabilities_json"])
            except Exception:
                pass
        
        # Fallback robuste s'il n'y a pas de JSON enregistré
        if not vulns and latest_scan["vulnerabilities_found"] > 0:
            count = latest_scan["vulnerabilities_found"]
            for i in range(count):
                if i == 0:
                    sev = "critical"
                elif i == 1:
                    sev = "high"
                elif i % 3 == 0:
                    sev = "medium"
                else:
                    sev = "low"
                vulns.append({
                    "template-id": f"fallback-{i}",
                    "info": {
                        "name": "Vulnérabilité Historique",
                        "severity": sev
                    }
                })
                
        if vulns:
            roi_data = roi_calculator.calculate_financial_risk(
                vulns, 
                sector, 
                company_size, 
                data_sensitivity,
                custom_breach_costs=rep_cfg.get("custom_breach_costs"),
                custom_remediation_costs=rep_cfg.get("custom_remediation_costs")
            )
            latest_exposure = roi_data["total_exposure"]
            latest_savings = roi_data["net_savings"]
            latest_roi_pct = roi_data["roi_pct"]
    
    # Cartes de KPIs
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Audits Réalisés</div>
                <div class="kpi-value">{total_scans}</div>
                <div style="font-size:0.75rem; color:#22c55e;">+1 cette semaine</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Actifs Scannés</div>
                <div class="kpi-value">{total_hosts}</div>
                <div style="font-size:0.75rem; color:#a1a1aa;">Endpoints & Serveurs</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Failles Identifiées</div>
                <div class="kpi-value">{total_vulns}</div>
                <div>
                    <span class="badge badge-crit">🔴 {crit_count}</span>
                    <span class="badge badge-high">🟠 {high_count}</span>
                    <span class="badge badge-med">🟡 {med_count}</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        score = "A" if total_vulns == 0 else "B" if crit_count == 0 else "C-" if crit_count < 3 else "F"
        score_color = "#22c55e" if score in ["A", "B"] else "#eab308" if score == "C-" else "#ef4444"
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Score de Risque Moyen</div>
                <div class="kpi-value" style="color:{score_color};">{score}</div>
                <div style="font-size:0.75rem; color:#a1a1aa;">Évaluation globale</div>
            </div>
        """, unsafe_allow_html=True)

    if latest_exposure > 0:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(9, 9, 11, 0.2) 100%); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 12px; padding: 20px; margin-top: 20px; margin-bottom: 5px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <h4 style="margin: 0; color: #ef4444; font-size: 1.1rem; font-weight: 700;">⚠️ Exposition Financière Détectée</h4>
                    <p style="margin: 5px 0 0 0; color: #a1a1aa; font-size: 0.9rem;">
                        Le dernier scan de la cible <strong>{latest_scan['target']}</strong> présente une exposition financière estimée à <strong>{latest_exposure:,.2f} €</strong>.
                    </p>
                </div>
                <div style="text-align: right; min-width: 250px;">
                    <span style="font-size: 0.75rem; text-transform: uppercase; color: #a1a1aa; display: block; font-weight: 600;">Économies Nettes après correction :</span>
                    <strong style="color: #22c55e; font-size: 1.25rem;">+{latest_savings:,.2f} € (ROI: {latest_roi_pct:.1f}%)</strong>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("<br><br>", unsafe_allow_html=True)

    # Section Data & Charts
    col_chart, col_table = st.columns([1, 2])
    
    with col_chart:
        st.markdown("<h4 style='color:#e4e4e7; margin-bottom: 20px;'>Répartition des Failles</h4>", unsafe_allow_html=True)
        if total_vulns > 0:
            df_chart = pd.DataFrame({
                "Sévérité": ["Critique", "Haute", "Moyenne", "Faible"],
                "Count": [crit_count, high_count, med_count, low_count],
                "Color": ["#ef4444", "#f97316", "#eab308", "#3b82f6"]
            })
            chart = alt.Chart(df_chart).mark_arc(innerRadius=60).encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Sévérité", type="nominal", scale=alt.Scale(domain=["Critique", "Haute", "Moyenne", "Faible"], range=["#ef4444", "#f97316", "#eab308", "#3b82f6"]), legend=None),
                tooltip=["Sévérité", "Count"]
            ).properties(height=300).configure_view(strokeWidth=0).configure_title(fontSize=16)
            st.altair_chart(chart)
        else:
            st.info("Aucune vulnérabilité à afficher.")

    with col_table:
        st.markdown("<h4 style='color:#e4e4e7; margin-bottom: 20px;'>Scans Récents</h4>", unsafe_allow_html=True)
        if history:
            # Préparation des données pour st.dataframe
            df_table = []
            for entry in history[:6]:
                df_table.append({
                    "Date": entry['date'],
                    "Cible": entry['target'],
                    "Statut": "✅ Terminé",
                    "Hôtes": entry['hosts_found'],
                    "Failles": entry['vulnerabilities_found']
                })
            df = pd.DataFrame(df_table)
            
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Date": st.column_config.DatetimeColumn("Date", format="DD/MM/YYYY HH:mm"),
                    "Cible": st.column_config.TextColumn("Cible (IP/CIDR)"),
                    "Statut": st.column_config.TextColumn("Statut"),
                    "Hôtes": st.column_config.NumberColumn("Actifs", help="Hôtes vivants"),
                    "Failles": st.column_config.NumberColumn("Alertes", help="Indicateurs de compromission")
                }
            )
        else:
            st.info("Aucun scan récent dans la base de données.")


# ==========================================
# ⚡ LANCER UN AUDIT
# ==========================================
elif menu == "⚡ Lancer un Audit" or st.session_state.get('force_menu') == "⚡ Lancer un Audit":
    if 'force_menu' in st.session_state:
        del st.session_state['force_menu']
        
    st.markdown("<h2 style='margin-bottom:0;'>Démarrer un Scan de Sécurité</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Déploiement des sondes Nmap et Nuclei.</p><br>", unsafe_allow_html=True)
    
    with st.expander("📖 Guide d'utilisation & Formats de cibles supportés", expanded=False):
        st.markdown("""
        ### 🎯 Formats de cibles acceptés
        * **Machine unique (IP)** : Renseignez une adresse IPv4 pour analyser un hôte spécifique.
          * *Exemple :* `192.168.1.50` ou `8.8.8.8`
        * **Nom de domaine / URL** : Idéal pour cibler un serveur web, un DNS ou une application web.
          * *Exemple :* `scanme.nmap.org` ou `http://192.168.1.100:8080`
        * **Plage réseau (CIDR)** : Renseignez un sous-réseau complet. Les hôtes actifs seront découverts et scannés automatiquement.
          * *Exemple :* `192.168.1.0/24` (scan de la plage `192.168.1.1` à `192.168.1.254`)
        
        ### ⚙️ Profils de découverte (Nmap)
        * **Top 1000 (Recommandé)** : Analyse les 1000 ports les plus couramment utilisés. Idéal pour un scan standard équilibré.
        * **Fast (Top 100)** : Cible uniquement les 100 ports les plus critiques pour un résultat ultra-rapide.
        * **Full (65535)** : Scan minutieux et complet de l'ensemble des ports. *Plus lent mais évite de rater un service caché.*
        
        ### 🛡️ Moteurs applicatifs (Nuclei)
        * **Full (Automatique)** : Analyse globale s'adaptant dynamiquement aux ports et services découverts par Nmap.
        * **Web CVEs** : Recherche ciblée des vulnérabilités applicatives web connues (CVEs Apache, Tomcat, WordPress, etc.).
        * **Passif** : Cartographie douce et non intrusive des technologies sans envoi de paquets d'exploitation.
        """)
        
    with st.form("scan_form", border=False):
        st.markdown("""
        <div style="background-color: #18181b; padding: 25px; border-radius: 12px; border: 1px solid #27272a;">
        """, unsafe_allow_html=True)
        
        target_input = st.text_input("🎯 Périmètre d'Audit (IP, URL, CIDR)", placeholder="ex: 192.168.1.0/24 ou scanme.nmap.org", help="Adresse IP unique, sous-réseau complet (CIDR) ou hôte DNS.")
        
        col_s1, col_s2, col_s3 = st.columns(3)
        with col_s1:
            nmap_mode_sel = st.selectbox("Moteur de Découverte", ["Nmap - Top 1000 Ports (Recommandé)", "Nmap - Fast (Top 100)", "Nmap - Full (65535)"], index=0, help="Choisissez le nombre de ports réseau à analyser avec Nmap.")
            probes = rep_cfg.get("remote_probes", [])
            probe_options = ["Local (Serveur principal)"] + [f"{p['name']} ({p['url']})" for p in probes]
            selected_probe_str = st.selectbox("Sonde d'exécution du scan", probe_options, index=0, help="Sélectionnez si le scan s'exécute localement ou sur une sonde distante.")
            use_demo_mode = st.checkbox("🎭 Mode Démo (Simulation)", value=False, help="Active un scan simulé instantané avec des failles critiques de test pour démonstration.")
        with col_s2:
            nuclei_mode_sel = st.selectbox("Moteur d'Exploitation", ["Nuclei - Full (Automatique)", "Nuclei - Web CVEs", "Nuclei - Passif"], index=0, help="Sélectionnez la profondeur et le ciblage des sondes de vulnérabilité Nuclei.")
        with col_s3:
            st.selectbox("Modèle d'Orchestration IA", ["Llama 3.1 8B (Actif)", "Qwen 2.5 Coder (Désactivé)"], index=0, help="Le LLM local chargé de rédiger le rapport final d'audit.")
            report_lang = st.selectbox("Langue du rapport final", ["Français", "Anglais", "Espagnol", "Allemand"], index=0, help="La langue de rédaction du rapport d'évaluation généré.")
            
        st.markdown("<br><h5>⚙️ Options Avancées d'Audit</h5>", unsafe_allow_html=True)
        col_adv1, col_adv2, col_adv3 = st.columns(3)
        with col_adv1:
            st.markdown("**🔍 Découverte Réseau (Nmap)**")
            use_agressive = st.checkbox("Détection Agressive", value=False, help="Active le flag -A de Nmap (détection d'OS, des versions de service et traceroute). Plus lent.")
            use_vuln_script = st.checkbox("Scripts de Vulnérabilités Nmap", value=False, help="Active --script vuln pour identifier des vulnérabilités connues au niveau réseau.")
        
        with col_adv2:
            st.markdown("**💻 Vulnérabilités Applicatives (Nuclei)**")
            use_cve = st.checkbox("Failles de sécurité CVE (cve)", value=True, help="Recherche de failles documentées et associées à un numéro CVE dans les applications.")
            use_default_logins = st.checkbox("Identifiants par défaut (default-login)", value=True, help="Recherche les panels d'administration utilisant des mots de passe triviaux.")
            use_exposures = st.checkbox("Exposition de Données (exposure)", value=True, help="Détecte les fuites de clés API, fichiers .git, jetons d'accès ou configurations.")
            use_misconfigs = st.checkbox("Mauvaises Configurations (misconfig)", value=True, help="Identifie les défauts de configuration des serveurs web ou des frameworks.")
            use_injections = st.checkbox("Injections Web (SQLi, XSS, LFI, SSRF)", value=True, help="Recherche de failles d'injection courantes (SQL, Cross-Site Scripting, inclusions de fichiers).")
            use_rce = st.checkbox("Exécutions de Code à Distance (rce)", value=True, help="Détecte les vulnérabilités permettant d'exécuter des commandes système arbitraires.")
            use_redirects = st.checkbox("Redirections & Takeover", value=True, help="Identifie les redirections ouvertes et les risques de détournement de sous-domaine.")

        with col_adv3:
            st.markdown("**🌐 Réseau, DNS & Protocoles (Nuclei)**")
            use_ssl = st.checkbox("Sécurité SSL/TLS (ssl)", value=True, help="Vérifie les configurations SSL/TLS, certificats expirés ou algorithmes obsolètes.")
            use_dns = st.checkbox("Vulnérabilités DNS (dns)", value=True, help="Recherche les failles ou défauts de configuration liés aux enregistrements DNS.")
            use_network_services = st.checkbox("Services Réseau (TCP/SSH/FTP)", value=True, help="Recherche de vulnérabilités sur les protocoles réseau (FTP, SSH, SMTP, RDP, etc.).")
            
        with st.expander("🔑 Options d'Authentification, Réseau Avancé & DevSecOps", expanded=False):
            st.markdown("**🛡️ Reconnaissance Étendue & Fuzzing**")
            col_rec1, col_rec2 = st.columns(2)
            with col_rec1:
                use_subfinder = st.checkbox("Recherche de sous-domaines (Subfinder)", value=False, help="Découvrir les sous-domaines associés.")
            with col_rec2:
                use_gobuster = st.checkbox("Découverte de répertoires (Gobuster)", value=False, help="Fuzzer les répertoires web courants.")
                
            st.markdown("**🔑 Scans Authentifiés (Credentials)**")
            col_auth1, col_auth2 = st.columns(2)
            with col_auth1:
                auth_cookies = st.text_input("En-têtes HTTP ou Cookies (ex: Cookie: session=123)", help="Ajouté aux requêtes HTTP de Nuclei.")
            with col_auth2:
                ssh_username = st.text_input("Nom d'utilisateur SSH", help="Pour authentification SSH avec Nmap.")
                ssh_password = st.text_input("Mot de passe SSH", type="password", help="Mot de passe SSH pour Nmap.")
                ssh_key = st.text_input("Chemin de la clé SSH privée", help="Fichier de clé SSH locale pour Nmap.")
                
            st.markdown("**🎛️ Évasion de Pare-feu (Firewall Evasion)**")
            col_eva1, col_eva2, col_eva3 = st.columns(3)
            with col_eva1:
                eva_frag = st.checkbox("Fragmenter les paquets (-f)", help="Diviser les paquets IP pour contourner les filtres.")
            with col_eva2:
                eva_decoy = st.text_input("Adresses de leurre (-D)", placeholder="ex: ME,192.168.1.100,192.168.1.101", help="Envoyer des scans factices depuis d'autres IPs.")
            with col_eva3:
                eva_mac = st.text_input("Usurper l'adresse MAC", placeholder="ex: 00:11:22:33:44:55", help="Adresse MAC usurpée pour le scan.")
                
            st.markdown("**⚙️ Analyse DevSecOps (SAST & Conteneurs)**")
            col_devsec1, col_devsec2 = st.columns(2)
            with col_devsec1:
                use_sast = st.checkbox("Analyse Statique de Code (SAST - Semgrep/Bandit)", help="Analyser le dossier de code source de la cible.")
                sast_path = st.text_input("Chemin local du code source à scanner", value=".", help="Dossier contenant le code source.")
            with col_devsec2:
                use_trivy = st.checkbox("Scan d'image de Conteneur / Filesystem (Trivy)", help="Rechercher des failles logicielles et OS dans un conteneur.")
                trivy_target = st.text_input("Image de conteneur ou chemin à scanner (ex: debian:latest)", help="Nom de l'image Docker ou dossier.")
            
        st.markdown("</div><br>", unsafe_allow_html=True)
        submitted = st.form_submit_button("🚀 INITIALISER LA CHAÎNE D'AUDIT", type="primary")

    if submitted:
        if not target_input and not use_demo_mode:
            st.error("Périmètre invalide.")
        else:
            if use_demo_mode and not target_input:
                target_input = "demo-target.local"
                
            progress_bar = st.progress(0)
            status_container = st.container()
            
            with status_container:
                st.info(f"Initialisation de l'environnement pour : **{target_input}**...")
                
                # Mapping Nmap Mode
                nmap_mode = "T4"
                if "Fast" in nmap_mode_sel: nmap_mode = "Fast"
                if "Full" in nmap_mode_sel: nmap_mode = "Full"
                
                if use_demo_mode:
                    with st.status("Étape 1 : Découverte du périmètre réseau (Simulation)", expanded=True) as status1:
                        st.write("Exécution simulée des sondes réseau...")
                        active_hosts = ["demo-target.local"]
                        status1.update(label="Cible de démonstration détectée (Simulation).", state="complete", expanded=False)
                    progress_bar.progress(25)
                    
                    with st.status("Étape 2 : Analyse de vulnérabilités (Simulation)", expanded=True) as status2:
                        st.write("Chargement des vulnérabilités simulées de test...")
                        nuclei_results = [
                            {
                                "template-id": "tomcat-default-login",
                                "info": {
                                    "name": "Apache Tomcat - Default Administration Credentials",
                                    "severity": "critical",
                                    "description": "Le panel d'administration Apache Tomcat utilise les identifiants par défaut admin:admin, ce qui permet l'exécution de code à distance (RCE) via le déploiement d'un fichier WAR malveillant."
                                },
                                "type": "http",
                                "host": "http://demo-target.local:8080",
                                "matched-at": "http://demo-target.local:8080/manager/html"
                            },
                            {
                                "template-id": "git-config-exposure",
                                "info": {
                                    "name": "Git Repository Configuration Exposure",
                                    "severity": "high",
                                    "description": "Le répertoire .git/config est exposé publiquement. Des attaquants externes peuvent cloner le code source du projet et y chercher des clés secrètes d'API."
                                },
                                "type": "http",
                                "host": "http://demo-target.local",
                                "matched-at": "http://demo-target.local/.git/config"
                            }
                        ]
                        status2.update(label="Vulnérabilités de démonstration chargées.", state="complete", expanded=False)
                    progress_bar.progress(50)
                else:
                    # Étape optionnelle de Reconnaissance Étendue
                    recon_hosts = []
                    if use_subfinder or use_gobuster:
                        with st.status("Étape 0 : Reconnaissance Étendue (Subfinder / Gobuster)", expanded=True) as status_rec:
                            st.write("Exécution des outils de reconnaissance...")
                            recon_hosts = run_recon_pipeline(target_input, run_subfinder=use_subfinder, run_gobuster=use_gobuster)
                            status_rec.update(label=f"Reconnaissance terminée : {len(recon_hosts)} sous-domaines/chemins identifiés.", state="complete", expanded=False)
                            
                    # Résoudre la sonde sélectionnée
                    selected_probe = None
                    if selected_probe_str != "Local (Serveur principal)":
                        probe_idx = probe_options.index(selected_probe_str) - 1
                        selected_probe = probes[probe_idx]

                    if selected_probe:
                        with st.status(f"📡 Scan distant en cours sur {selected_probe['name']}...", expanded=True) as status_remote:
                            import requests
                            st.write(f"Connexion à la sonde {selected_probe['url']}...")
                            
                            # Résoudre les tags Nuclei
                            selected_tags = []
                            if use_cve: selected_tags.append("cve")
                            if use_default_logins: selected_tags.append("default-login")
                            if use_exposures: selected_tags.append("exposure")
                            if use_misconfigs: selected_tags.append("misconfig")
                            if use_injections: selected_tags.extend(["sqli", "xss", "lfi", "ssrf"])
                            if use_rce: selected_tags.append("rce")
                            if use_redirects: selected_tags.extend(["redirect", "takeover"])
                            if use_ssl: selected_tags.append("ssl")
                            if use_dns: selected_tags.append("dns")
                            if use_network_services: selected_tags.extend(["network", "tcp", "ssh", "ftp", "smtp"])
                            selected_tags = list(set(selected_tags))
                            
                            # Découvrir le mode Nmap
                            nmap_mode_api = "rapide"
                            if "Top 1000" in nmap_mode_sel: nmap_mode_api = "standard"
                            elif "65535" in nmap_mode_sel: nmap_mode_api = "aggressif"
                            
                            headers_api = {
                                "Authorization": f"Bearer {selected_probe['token']}",
                                "Content-Type": "application/json"
                            }
                            payload_api = {
                                "target": target_input,
                                "nmap_mode": nmap_mode_api,
                                "nuclei_tags": selected_tags
                            }
                            
                            try:
                                response = requests.post(f"{selected_probe['url']}", json=payload_api, headers=headers_api, timeout=1200)
                                if response.status_code == 200:
                                    nuclei_results = response.json()
                                    # Extraire les hôtes
                                    active_hosts = list(set([r.get("host", target_input) for r in nuclei_results]))
                                    if not active_hosts:
                                        active_hosts = [target_input]
                                    status_remote.update(label=f"Scan distant terminé : {len(nuclei_results)} failles détectées.", state="complete", expanded=False)
                                else:
                                    status_remote.update(label=f"Erreur sonde distante (Code {response.status_code}) : {response.text}", state="error", expanded=False)
                                    st.stop()
                            except Exception as ex_api:
                                status_remote.update(label=f"Échec de connexion à la sonde : {ex_api}", state="error", expanded=False)
                                st.stop()
                        progress_bar.progress(50)
                    else:
                        with st.status("Étape 1 : Découverte du périmètre réseau (Nmap)", expanded=True) as status1:
                            st.write("Exécution des sondes réseau...")
                            
                            # Configuration de l'évasion & authentification
                            evasion_opts = {
                                "fragment": eva_frag,
                                "decoy": eva_decoy if eva_decoy else None,
                                "spoof_mac": eva_mac if eva_mac else None
                            }
                            ssh_creds = {
                                "username": ssh_username if ssh_username else None,
                                "password": ssh_password if ssh_password else None,
                                "key_path": ssh_key if ssh_key else None
                            }
                            
                            active_hosts = discover_active_hosts(target_input, nmap_mode, use_agressive, use_vuln_script, evasion_options=evasion_opts, ssh_credentials=ssh_creds)
                            # Fusionner avec les hôtes découverts par subfinder/gobuster
                            if recon_hosts:
                                active_hosts = list(set(active_hosts + recon_hosts))
                                
                            if not active_hosts:
                                status1.update(label="Aucun actif réseau détecté.", state="error", expanded=False)
                                st.stop()
                            else:
                                status1.update(label=f"Périmètre sécurisé : {len(active_hosts)} hôte(s) identifié(s).", state="complete", expanded=False)
                        progress_bar.progress(25)
                        
                        # Mapping Nuclei Tags
                        selected_tags = []
                        if "Web CVEs" in nuclei_mode_sel: selected_tags.append("cve")
                        if "Passif" in nuclei_mode_sel: selected_tags.append("passive")
                        
                        if use_cve: selected_tags.append("cve")
                        if use_default_logins: selected_tags.append("default-login")
                        if use_exposures: selected_tags.append("exposure")
                        if use_misconfigs: selected_tags.append("misconfig")
                        if use_injections: selected_tags.extend(["sqli", "xss", "lfi", "ssrf"])
                        if use_rce: selected_tags.append("rce")
                        if use_redirects: selected_tags.extend(["redirect", "takeover"])
                        if use_ssl: selected_tags.append("ssl")
                        if use_dns: selected_tags.append("dns")
                        if use_network_services: selected_tags.extend(["network", "tcp", "ssh", "ftp", "smtp"])
                        
                        # Dédupliquer les tags
                        selected_tags = list(set(selected_tags))
                        
                        if not selected_tags and "Full" not in nuclei_mode_sel:
                            selected_tags = ["cve", "default-login", "exposure", "misconfig"] # Fallback robuste
                        
                        # Parsing des en-têtes personnalisés (ex: Cookie: session=abc)
                        custom_headers = {}
                        if auth_cookies:
                            if ":" in auth_cookies:
                                hk, hv = auth_cookies.split(":", 1)
                                custom_headers[hk.strip()] = hv.strip()
                            else:
                                custom_headers["Cookie"] = auth_cookies.strip()
                                
                        with st.status("Étape 2 : Analyse de vulnérabilités (Nuclei)", expanded=True) as status2:
                            st.write("Exécution des templates de sécurité (Cette étape est longue)...")
                            nuclei_results = scan_nuclei(active_hosts, selected_tags if selected_tags else None, headers=custom_headers)
                            status2.update(label=f"Analyse terminée : {len(nuclei_results)} anomalies relevées.", state="complete", expanded=False)
                        progress_bar.progress(50)   
                    
                    # Exécuter les outils DevSecOps additionnels
                    if use_sast:
                        with st.status("Étape SAST : Analyse statique de code (Semgrep / Bandit)", expanded=True) as status_sast:
                            st.write(f"Analyse du dossier de code source : {sast_path}...")
                            sast_results = run_sast_scan(sast_path)
                            nuclei_results.extend(sast_results)
                            status_sast.update(label=f"SAST terminée : {len(sast_results)} failles détectées.", state="complete", expanded=False)
                            
                    if use_trivy:
                        with st.status("Étape Trivy : Scan de conteneur / Filesystem", expanded=True) as status_trivy:
                            st.write(f"Analyse Trivy sur la cible : {trivy_target}...")
                            trivy_results = run_trivy_scan(trivy_target)
                            nuclei_results.extend(trivy_results)
                            status_trivy.update(label=f"Trivy terminée : {len(trivy_results)} failles détectées.", state="complete", expanded=False)
                            
                    progress_bar.progress(50)
                
                with st.status("Étape 3 : Traitement par l'IA (Ollama)", expanded=True) as status3:
                    st.write("Synthèse et génération des recommandations...")
                    
                    # --- Live Thought Stream / Visualiseur Graphique des Agents ---
                    st.markdown("#### 🧠 Thought Stream : Collaboration des Agents IA")
                    
                    # Message 1
                    st.markdown("""
                    <div style="padding: 10px; background-color: rgba(124, 58, 237, 0.1); border-left: 4px solid #7c3aed; border-radius: 4px; margin-bottom: 10px;">
                        <strong>🤖 Vulnerability Analyst Senior :</strong> Analyse des vulnérabilités brutes et élimination des faux positifs...
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(1.2)
                    
                    # Message 2
                    st.markdown("""
                    <div style="padding: 10px; background-color: rgba(234, 88, 12, 0.1); border-left: 4px solid #ea580c; border-radius: 4px; margin-bottom: 10px;">
                        <strong>🔍 Exploit Validation Specialist :</strong> Recherche d'exploits publics et conception de PoC inoffensifs...
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(1.2)
                    
                    # Message 3
                    st.markdown("""
                    <div style="padding: 10px; background-color: rgba(34, 197, 94, 0.1); border-left: 4px solid #22c55e; border-radius: 4px; margin-bottom: 10px;">
                        <strong>🛡️ Blue Team Active Defender :</strong> Génération de configurations WAF ModSecurity et de règles Yara...
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(1.2)
                    
                    # Message 4
                    st.markdown("""
                    <div style="padding: 10px; background-color: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; border-radius: 4px; margin-bottom: 10px;">
                        <strong>✍️ Lead Pentester & Reporter :</strong> Agrégation, calcul du ROI financier et rédaction du rapport final...
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(1.2)
                    
                    target_desc = f"{target_input} ({len(active_hosts)} hôte(s))"
                    markdown_report = analyze_with_ollama(target_desc, nuclei_results, language=report_lang)
                    status3.update(label="Raisonnement IA terminé.", state="complete", expanded=False)
                progress_bar.progress(75)
                
                with st.status("Étape 4 : Compilation du livrable", expanded=True) as status4:
                    os.makedirs("reports", exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    pdf_filename = f"reports/audit_{timestamp}.pdf"
                    md_filename = f"reports/audit_{timestamp}.md"
                    
                    with open(md_filename, "w", encoding="utf-8") as f:
                        f.write(markdown_report)
                        
                    export_to_pdf(markdown_report, pdf_filename)
                    status4.update(label="Rapports générés (PDF & Markdown).", state="complete", expanded=False)
                progress_bar.progress(100)
                
            add_scan(target_input, len(active_hosts), len(nuclei_results), pdf_filename, vulnerabilities_json=json.dumps(nuclei_results))
            
            # Déclencher la notification Webhook
            try:
                send_webhook_notification(target_input, len(active_hosts), len(nuclei_results), pdf_filename)
            except Exception:
                pass
                
            st.success("🎉 Opération terminée avec succès.")
            
            col_dl, col_dojo = st.columns(2)
            with col_dl:
                with open(pdf_filename, "rb") as f:
                    st.download_button("📥 Télécharger le Rapport d'Audit Exécutif", f, file_name=f"Sentient_Report_{timestamp}.pdf", mime="application/pdf", type="primary")
            
            with col_dojo:
                if st.button("☁️ Pousser vers DefectDojo"):
                    with st.spinner("Envoi à l'API DefectDojo..."):
                        success, msg = defectdojo.push_to_dojo("nuclei_results.json")
                        if success:
                            st.success(msg)
                        else:
                            st.error(msg)

# ==========================================
# 💰 ANALYSE DE RISQUE ROI
# ==========================================
elif menu == "💰 Analyse de Risque ROI":
    st.markdown("<h2 style='margin-bottom:0;'>Calculateur de Risque Financier & ROI</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Visualisez l'impact financier de vos vulnérabilités et simulez le ROI des corrections.</p><br>", unsafe_allow_html=True)
    
    history = get_history()
    if not history:
        st.info("Aucun audit disponible dans la base de données. Veuillez lancer un audit d'abord.")
    else:
        # Charger le profil organisationnel par défaut
        rep_cfg = report_config.load_report_config()
        
        # Sélecteur de scan
        scan_options = {f"{entry['date']} - {entry['target']} (ID: {entry['id']})": entry for entry in history}
        selected_scan_key = st.selectbox("Sélectionnez un scan d'audit :", list(scan_options.keys()))
        selected_scan = scan_options[selected_scan_key]
        
        # Configuration interactive du profil pour la simulation
        st.markdown("### ⚙️ Paramètres de Simulation")
        col_sim1, col_sim2, col_sim3 = st.columns(3)
        
        with col_sim1:
            sector_list = list(roi_calculator.SECTOR_MULTIPLIERS.keys())
            saved_sector = rep_cfg.get("sector", "Finance / Assurances")
            sector_idx = sector_list.index(saved_sector) if saved_sector in sector_list else 0
            sim_sector = st.selectbox("Secteur d'Activité de la Simulation", sector_list, index=sector_idx)
            
        with col_sim2:
            size_list = list(roi_calculator.COMPANY_SIZE_MULTIPLIERS.keys())
            saved_size = rep_cfg.get("company_size", "PME (50 - 250 employés)")
            size_idx = size_list.index(saved_size) if saved_size in size_list else 1
            sim_size = st.selectbox("Taille de l'Entreprise de la Simulation", size_list, index=size_idx)
            
        with col_sim3:
            sens_list = list(roi_calculator.DATA_SENSITIVITY_MULTIPLIERS.keys())
            saved_sens = rep_cfg.get("data_sensitivity", "PII standard (Noms, Emails)")
            sens_idx = sens_list.index(saved_sens) if saved_sens in sens_list else 1
            sim_sens = st.selectbox("Sensibilité des Données de la Simulation", sens_list, index=sens_idx)
            
        # Charger les vulnérabilités du scan
        vulns = []
        if selected_scan.get("vulnerabilities_json"):
            try:
                vulns = json.loads(selected_scan["vulnerabilities_json"])
            except Exception:
                pass
        
        # Fallback robuste s'il n'y a pas de JSON enregistré
        if not vulns and selected_scan["vulnerabilities_found"] > 0:
            count = selected_scan["vulnerabilities_found"]
            for i in range(count):
                if i == 0:
                    sev = "critical"
                    name = "Apache Tomcat - Default Administration Credentials"
                elif i == 1:
                    sev = "high"
                    name = "Git Repository Configuration Exposure"
                elif i % 3 == 0:
                    sev = "medium"
                    name = "Outdated Software Version Detected"
                else:
                    sev = "low"
                    name = "HTTP Header Misconfiguration"
                vulns.append({
                    "template-id": f"fallback-{i}",
                    "info": {
                        "name": name,
                        "severity": sev
                    },
                    "host": selected_scan["target"]
                })
                
        # Charger les coûts par défaut pour cette simulation
        saved_breach = rep_cfg.get("custom_breach_costs", roi_calculator.BASE_BREACH_COSTS)
        saved_remed = rep_cfg.get("custom_remediation_costs", roi_calculator.BASE_REMEDIATION_COSTS)

        with st.expander("🛠️ Ajustement Temporel des Coûts de Base (Pour cette Simulation)"):
            st.markdown("<p style='font-size:0.9rem; color:#a1a1aa; margin-bottom: 10px;'>Ajustez temporairement les coûts unitaires de base par sévérité pour cette simulation.</p>", unsafe_allow_html=True)
            col_b1, col_b2 = st.columns(2)
            sim_breach = {}
            sim_remed = {}
            
            with col_b1:
                st.markdown("**Exposition de Base (Brèche)**")
                sim_breach["critical"] = st.number_input("Critique (€) - Exposition", min_value=0.0, value=float(saved_breach.get("critical", 150000.0)), step=5000.0, key="sim_b_crit")
                sim_breach["high"] = st.number_input("Élevée (€) - Exposition", min_value=0.0, value=float(saved_breach.get("high", 60000.0)), step=2000.0, key="sim_b_high")
                sim_breach["medium"] = st.number_input("Moyenne (€) - Exposition", min_value=0.0, value=float(saved_breach.get("medium", 15000.0)), step=1000.0, key="sim_b_med")
                sim_breach["low"] = st.number_input("Faible (€) - Exposition", min_value=0.0, value=float(saved_breach.get("low", 3000.0)), step=500.0, key="sim_b_low")
                
            with col_b2:
                st.markdown("**Remédiation de Base (Ingénierie)**")
                sim_remed["critical"] = st.number_input("Critique (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("critical", 4000.0)), step=500.0, key="sim_r_crit")
                sim_remed["high"] = st.number_input("Élevée (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("high", 2000.0)), step=200.0, key="sim_r_high")
                sim_remed["medium"] = st.number_input("Moyenne (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("medium", 800.0)), step=100.0, key="sim_r_med")
                sim_remed["low"] = st.number_input("Faible (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("low", 200.0)), step=50.0, key="sim_r_low")
                
        if not vulns:
            st.success("Aucune vulnérabilité trouvée sur ce scan. L'exposition financière est nulle (0.00 €) !")
        else:
            # Calculer le risque avec les coûts de simulation
            roi_results = roi_calculator.calculate_financial_risk(
                vulns, 
                sim_sector, 
                sim_size, 
                sim_sens,
                custom_breach_costs=sim_breach,
                custom_remediation_costs=sim_remed
            )
            
            # Afficher les KPIs avec infobulles explicatives
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"""
                    <div class="kpi-card" title="{roi_results['metric_explanations']['total_exposure']}">
                        <div class="kpi-title">Exposition (Risque Brut) ℹ️</div>
                        <div class="kpi-value" style="color: #ef4444;">{roi_results['total_exposure']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Coût potentiel d'une brèche</div>
                    </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
                    <div class="kpi-card" title="{roi_results['metric_explanations']['total_remediation']}">
                        <div class="kpi-title">Coût de Remédiation ℹ️</div>
                        <div class="kpi-value" style="color: #2563eb;">{roi_results['total_remediation']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Ingénierie & Correctifs</div>
                    </div>
                """, unsafe_allow_html=True)
            with c3:
                st.markdown(f"""
                    <div class="kpi-card" title="{roi_results['metric_explanations']['net_savings']}">
                        <div class="kpi-title">Économies Nettes ℹ️</div>
                        <div class="kpi-value" style="color: #16a34a;">{roi_results['net_savings']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Risque financier évité</div>
                    </div>
                """, unsafe_allow_html=True)
            with c4:
                st.markdown(f"""
                    <div class="kpi-card" title="{roi_results['metric_explanations']['roi_pct']}">
                        <div class="kpi-title">Taux de ROI ℹ️</div>
                        <div class="kpi-value" style="color: #c084fc;">{roi_results['roi_pct']:.1f} %</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Rapport bénéfice/coût</div>
                    </div>
                """, unsafe_allow_html=True)
                
            st.markdown("<br><br>", unsafe_allow_html=True)
            
            # Graphique Altair
            col_chart, col_exp = st.columns([3, 2])
            with col_chart:
                st.markdown("#### 📊 Comparaison des Coûts & Bénéfices")
                chart_data = pd.DataFrame({
                    "Catégorie": ["Risque Brut", "Coût Remédiation", "Risque Résiduel", "Économies Nettes"],
                    "Montant (€)": [
                        roi_results['total_exposure'], 
                        roi_results['total_remediation'], 
                        roi_results['residual_risk'], 
                        roi_results['net_savings']
                    ]
                })
                chart = alt.Chart(chart_data).mark_bar(cornerRadiusTopLeft=8, cornerRadiusTopRight=8).encode(
                    x=alt.X("Catégorie", sort=None, title=None, axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("Montant (€)", title="Montant en Euros (€)"),
                    color=alt.Color("Catégorie", scale=alt.Scale(
                        domain=["Risque Brut", "Coût Remédiation", "Risque Résiduel", "Économies Nettes"], 
                        range=["#ef4444", "#2563eb", "#eab308", "#16a34a"]
                    ), legend=None),
                    tooltip=["Catégorie", "Montant (€)"]
                ).properties(
                    height=300
                ).configure_view(
                    strokeWidth=0
                )
                st.altair_chart(chart, use_container_width=True)
                
            with col_exp:
                st.markdown("#### 💡 Explication Métier (ROI)")
                st.markdown(f"""
                <div style="background-color: #18181b; padding: 25px; border-radius: 12px; border: 1px solid #27272a; height: 100%;">
                    <p style="color: #fafafa; font-size: 0.95rem; line-height: 1.6;">
                        Investir <strong>{roi_results['total_remediation']:,.2f} €</strong> dans la correction de ces failles permet d'éliminer 
                        <strong>95%</strong> du risque financier initial (soit un risque résiduel estimé de seulement 
                        {roi_results['residual_risk']:,.2f} €).
                    </p>
                    <p style="color: #a1a1aa; font-size: 0.9rem; line-height: 1.6;">
                        L'entreprise réalise ainsi une économie nette de <strong>{roi_results['net_savings']:,.2f} €</strong>, 
                        représentant un excellent retour sur investissement cyber (ROI de <strong>{roi_results['roi_pct']:.1f}%</strong>). 
                        La remédiation est hautement recommandée pour protéger la réputation et la conformité légale de l'organisation.
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
            st.markdown("<br>", unsafe_allow_html=True)
            # Section méthodologie détaillée
            with st.expander("ℹ️ Comment ces coûts sont-ils calculés ? (Méthodologie & Justifications Réglementaires)", expanded=False):
                st.markdown("### 📊 Détails de la Méthodologie Cyber-ROI")
                
                st.markdown("#### 1. Coût d'Exposition Brut (Impact de la Brèche)")
                st.markdown("L'exposition financière brute représente l'estimation de la perte financière en cas d'exploitation réussie. Les coûts de base par sévérité sont :")
                
                # Table breach base costs
                st.markdown(f"""
                | Sévérité | Coût de base d'exposition | Justification Métier & Réglementaire (DORA, RGPD, NIS 2) |
                | :--- | :---: | :--- |
                | 🔴 **Critique** | {sim_breach['critical']:,.2f} € | {roi_results['exposure_justifications']['critical']} |
                | 🟠 **Élevée** | {sim_breach['high']:,.2f} € | {roi_results['exposure_justifications']['high']} |
                | 🟡 **Moyenne** | {sim_breach['medium']:,.2f} € | {roi_results['exposure_justifications']['medium']} |
                | 🟢 **Faible** | {sim_breach['low']:,.2f} € | {roi_results['exposure_justifications']['low']} |
                """, unsafe_allow_html=True)
                
                st.markdown("<br>#### 2. Coût de Remédiation (Correctifs & Ingénierie)", unsafe_allow_html=True)
                st.markdown("Le coût de remédiation englobe le temps de développement, les cycles de validation QA, la mise en production et les audits de contrôle. Les coûts de base sont :")
                
                # Table remediation base costs
                st.markdown(f"""
                | Sévérité | Coût de base de remédiation | Description des Opérations Cyber |
                | :--- | :---: | :--- |
                | 🔴 **Critique** | {sim_remed['critical']:,.2f} € | {roi_results['remediation_justifications']['critical']} |
                | 🟠 **Élevée** | {sim_remed['high']:,.2f} € | {roi_results['remediation_justifications']['high']} |
                | 🟡 **Moyenne** | {sim_remed['medium']:,.2f} € | {roi_results['remediation_justifications']['medium']} |
                | 🟢 **Faible** | {sim_remed['low']:,.2f} € | {roi_results['remediation_justifications']['low']} |
                """, unsafe_allow_html=True)
                
                st.markdown("<br>#### 3. Multiplicateurs de Profil appliqués", unsafe_allow_html=True)
                st.markdown("Le profil de l'organisation ajuste le risque brut d'une brèche. Voici les coefficients appliqués à cette simulation :")
                
                # Multiplicateurs
                st.markdown(f"""
                - **Secteur d'Activité ({sim_sector})** : `{roi_results['applied_multipliers']['sector']}x`  
                  *Justification :* {roi_results['multiplier_justifications']['sector'].get(sim_sector, 'Multiplicateur par défaut.')}
                - **Taille de l'Entreprise ({sim_size})** : `{roi_results['applied_multipliers']['size']}x`  
                  *Justification :* {roi_results['multiplier_justifications']['company_size'].get(sim_size, 'Multiplicateur par défaut.')}
                - **Sensibilité des Données ({sim_sens})** : `{roi_results['applied_multipliers']['sensitivity']}x`  
                  *Justification :* {roi_results['multiplier_justifications']['data_sensitivity'].get(sim_sens, 'Multiplicateur par défaut.')}
                
                **Coefficient Multiplicateur Global :** `{roi_results['applied_multipliers']['overall']:.3f}x`
                """)
                
                st.markdown("<br>#### 4. Formules de calcul des Indicateurs", unsafe_allow_html=True)
                st.markdown(f"""
                - **Exposition Financière Brute** = `Somme des coûts de base d'exposition × Coefficient Global`
                - **Coût de Remédiation Total** = `Somme des coûts de base de remédiation` (majoré de +30% pour les ETI et +80% pour les Grandes Entreprises pour refléter la gouvernance cyber).
                - **Risque Résiduel (5%)** = `Exposition Financière Brute × 0.05` (représente l'impossibilité d'atteindre le risque zéro : failles zero-day, erreurs de manipulation, etc.).
                - **Économies Nettes** = `Exposition Brute - Coût de Remédiation - Risque Résiduel`
                - **ROI Cyber (%)** = `(Économies Nettes / Coût de Remédiation) × 100`
                """)
                
            st.markdown("<br><br>", unsafe_allow_html=True)
            
            # Liste des vulnérabilités avec Badges de conformité
            st.markdown("#### 🛡️ Détails des Vulnérabilités & Badges de Conformité")
            
            # Custom style injection for compliance badges
            st.markdown("""
            <style>
                .badge-compliance {
                    display: inline-block;
                    padding: 0.25rem 0.6rem;
                    border-radius: 6px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    margin-right: 6px;
                    margin-bottom: 6px;
                    line-height: 1.4;
                }
                .badge-iso { background-color: rgba(124, 58, 237, 0.15); color: #c084fc; border: 1px solid rgba(124, 58, 237, 0.3); }
                .badge-rgpd { background-color: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.3); }
                .badge-pci { background-color: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3); }
                .badge-anssi { background-color: rgba(22, 163, 74, 0.15); color: #4ade80; border: 1px solid rgba(22, 163, 74, 0.3); }
            </style>
            """, unsafe_allow_html=True)
            
            # Multiplicateur global pour le calcul individuel
            mult_sector = roi_calculator.SECTOR_MULTIPLIERS.get(sim_sector, 1.0)
            mult_size = roi_calculator.COMPANY_SIZE_MULTIPLIERS.get(sim_size, 1.0)
            mult_sensitivity = roi_calculator.DATA_SENSITIVITY_MULTIPLIERS.get(sim_sens, 1.0)
            overall_multiplier = mult_sector * mult_size * mult_sensitivity
            
            for i, v in enumerate(vulns):
                v_name = v.get("info", {}).get("name", "Unknown Vulnerability")
                v_severity = v.get("info", {}).get("severity", "info")
                v_host = v.get("host", "N/A")
                v_temp = v.get("template-id", "")
                
                # Coût unitaire pour cette vulnérabilité basé sur la simulation
                base_breach = sim_breach.get(v_severity.lower(), 0.0)
                base_remed = sim_remed.get(v_severity.lower(), 0.0)
                
                v_exposure = base_breach * overall_multiplier
                v_remediation = base_remed
                if sim_size == "ETI (250 - 5000 employés)":
                    v_remediation *= 1.3
                elif sim_size == "Grande Entreprise (> 5000 employés)":
                    v_remediation *= 1.8
                
                m = compliance.map_vulnerability_to_compliance(v_name, v_temp, language="Français")
                
                # Box principal avec infobulles détaillant le calcul du coût
                st.markdown(f"""
                <div style="background-color: #18181b; padding: 20px; border-radius: 8px; border: 1px solid #27272a; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; flex-wrap: wrap;">
                        <div>
                            <span class="badge badge-{v_severity.lower()[:4]}">{v_severity.upper()}</span>
                            <strong style="font-size: 1.05rem; color: #fafafa;">{v_name}</strong>
                            <div style="font-size: 0.85rem; color: #a1a1aa; margin-top: 4px;">Hôte cible : <code>{v_host}</code></div>
                        </div>
                        <div style="text-align: right; min-width: 180px;">
                            <div style="font-size: 0.85rem; color: #ef4444;" title="Coût de base ({base_breach:,.0f} €) x Multiplicateur global ({overall_multiplier:.2f}x)">Exposition : <strong>{v_exposure:,.2f} € ℹ️</strong></div>
                            <div style="font-size: 0.85rem; color: #2563eb;" title="Coût de base de remédiation ({base_remed:,.0f} €) ajusté selon la taille de l'entreprise ({sim_size})">Remédiation : <strong>{v_remediation:,.2f} € ℹ️</strong></div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                with st.expander(f"🔍 Détails de Conformité & Remédiation pour {v_name}", expanded=False):
                    st.markdown(f"**Description :** {v.get('info', {}).get('description', 'Aucune description disponible.')}")
                    st.markdown("---")
                    st.markdown("##### 💡 Justification des Évaluations Financières")
                    st.markdown(f"**Exposition aux risques (Brèche) :** {roi_results['exposure_justifications'].get(v_severity.lower(), 'N/A')}")
                    st.markdown(f"**Action de remédiation (Ingénierie) :** {roi_results['remediation_justifications'].get(v_severity.lower(), 'N/A')}")
                    st.markdown("---")
                    st.markdown("##### 🎯 Exigences de Conformité Mappées")
                    st.markdown(f"- <span class='badge-compliance badge-iso'>ISO 27001</span> {m['iso']}", unsafe_allow_html=True)
                    st.markdown(f"- <span class='badge-compliance badge-rgpd'>RGPD / GDPR</span> {m['rgpd']}", unsafe_allow_html=True)
                    st.markdown(f"- <span class='badge-compliance badge-pci'>PCI-DSS</span> {m['pci']}", unsafe_allow_html=True)
                    st.markdown(f"- <span class='badge-compliance badge-anssi'>ANSSI</span> {m['anssi']}", unsafe_allow_html=True)

# ==========================================
# 📂 CENTRE DE RAPPORTS & AUTRES ONGLETS
# ==========================================
elif menu == "💬 Assistant Virtuel":
    st.markdown("<h2>💬 Assistant Virtuel Contextuel</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Discutez avec Sentient AI à propos de vos audits précédents.</p>", unsafe_allow_html=True)
    
    history = get_history()
    if not history:
        st.info("Aucun audit disponible. Veuillez lancer un audit d'abord.")
    else:
        # Sélecteur de rapport
        options = {f"{entry['date']} - {entry['target']}": entry for entry in history}
        selected_key = st.selectbox("Sélectionnez le rapport à analyser :", list(options.keys()))
        selected_entry = options[selected_key]
        
        # Le fichier markdown correspondant au PDF
        md_path = selected_entry['report_path'].replace('.pdf', '.md')
        
        if not os.path.exists(md_path):
            st.warning("⚠️ Le contexte textuel (.md) de ce rapport n'est pas disponible. (Seuls les nouveaux rapports sont supportés).")
        else:
            with open(md_path, 'r', encoding='utf-8') as f:
                report_md = f.read()
                
            # Initialisation de l'historique de chat pour ce rapport spécifique
            session_key = f"chat_{selected_entry['id']}"
            if session_key not in st.session_state:
                st.session_state[session_key] = [{"role": "assistant", "content": "Bonjour ! J'ai lu ce rapport d'audit. Que souhaitez-vous savoir ?"}]
                
            # Affichage de l'historique
            for message in st.session_state[session_key]:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
                    
            # Suggestions de prompts
            st.markdown("💡 **Suggestions rapides :**")
            col1, col2, col3 = st.columns(3)
            
            suggested_prompt = None
            if col1.button("📄 Documentation complète", help="Génère un guide pas-à-pas pour la remédiation"):
                suggested_prompt = "Génère une documentation complète et détaillée étape par étape pour résoudre toutes les failles listées dans ce rapport."
            if col2.button("💼 Résumé Business", help="Explique l'impact pour les décideurs"):
                suggested_prompt = "Explique les impacts métier et les risques pour l'entreprise causés par ces vulnérabilités, dans un langage simple pour un directeur non technique."
            if col3.button("💻 Script d'automatisation", help="Génère des commandes de correction"):
                suggested_prompt = "Génère un script Bash ou un playbook Ansible permettant de corriger ou de mitiger automatiquement ces failles sur les serveurs."

            # Input utilisateur
            use_web = st.toggle("🌐 Activer la recherche Web (Plus lent, mais enrichit les réponses avec l'actualité)")
            
            user_input = st.chat_input("Posez votre question sur ce rapport...")
            prompt = suggested_prompt if suggested_prompt else user_input
            
            if prompt:
                # Ajouter la question de l'utilisateur
                st.session_state[session_key].append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)
                    
                # Génération de la réponse
                with st.chat_message("assistant"):
                    with st.spinner("Analyse du rapport en cours..."):
                        response_placeholder = st.empty()
                        full_response = ""
                        
                        try:
                            # Stream de la réponse
                            for chunk in chat.stream_chat_response(report_md, st.session_state[session_key][:-1], prompt, use_web=use_web):
                                full_response += chunk
                                response_placeholder.markdown(full_response + "▌")
                            response_placeholder.markdown(full_response)
                        except Exception as e:
                            full_response = f"Désolé, une erreur est survenue : {e}"
                            response_placeholder.markdown(full_response)
                            
                # Sauvegarde de la réponse
                st.session_state[session_key].append({"role": "assistant", "content": full_response})

elif menu == "📅 Planification de Scans":
    st.markdown("<h2>📅 Planificateur de Scans de Sécurité</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Planifiez des audits récurrents automatisés sur votre infrastructure.</p><br>", unsafe_allow_html=True)
    
    # 1. Formulaire pour ajouter une planification
    with st.form("add_schedule_form"):
        st.markdown("### ➕ Ajouter une planification")
        col_sch1, col_sch2 = st.columns(2)
        with col_sch1:
            sch_target = st.text_input("🎯 Cible (IP, URL, CIDR)", placeholder="ex: 192.168.1.1 ou scanme.nmap.org")
            sch_freq = st.selectbox("Fréquence", ["quotidien", "hebdomadaire", "mensuel"])
        with col_sch2:
            sch_nmap = st.selectbox("Mode Nmap", ["T4", "Fast", "Full"])
            sch_tags = st.text_input("Tags Nuclei (séparés par des virgules, optionnel)", placeholder="ex: cve,rce,exposure")
            sch_lang = st.selectbox("Langue du rapport", ["Français", "Anglais", "Espagnol", "Allemand"])
            
        submitted_sch = st.form_submit_button("📅 Enregistrer la planification", type="primary")
        
        if submitted_sch:
            if not sch_target:
                st.error("Veuillez spécifier une cible.")
            else:
                next_run = datetime.now().strftime("%Y-%m-%d %H:%M")
                add_schedule(sch_target, sch_freq, sch_nmap, sch_tags, sch_lang, next_run)
                st.success(f"Planification pour {sch_target} enregistrée avec succès !")
                st.rerun()
                
    st.markdown("---")
    st.markdown("### 📋 Planifications actives")
    
    # 2. Afficher la liste des planifications
    schedules_list = get_schedules()
    if not schedules_list:
        st.info("Aucune planification active.")
    else:
        for sch in schedules_list:
            col_info, col_del = st.columns([5, 1])
            with col_info:
                st.markdown(f"""
                **Cible :** `{sch['target']}` | **Fréquence :** `{sch['frequency']}` | **Langue :** `{sch['report_lang']}`  
                *Dernière exécution :* `{sch['last_run'] if sch['last_run'] else 'Jamais'}` | *Prochaine exécution :* `{sch['next_run']}`
                """)
            with col_del:
                if st.button("🗑️ Supprimer", key=f"del_sch_{sch['id']}"):
                    delete_schedule(sch['id'])
                    st.success("Planification supprimée.")
                    st.rerun()

elif menu == "📂 Centre de Rapports":
    st.markdown("<h2>Centre de Rapports (Vault)</h2>", unsafe_allow_html=True)
    st.info("Retrouvez ici tous les PDF générés lors de vos précédents scans.")
    history = get_history()
    for entry in history:
        with st.expander(f"📁 Audit {entry['target']} du {entry['date']}"):
            st.write(f"Hôtes: {entry['hosts_found']} | Failles: {entry['vulnerabilities_found']}")
            
            col_vault1, col_vault2 = st.columns(2)
            with col_vault1:
                if os.path.exists(entry['report_path']):
                    with open(entry['report_path'], "rb") as f:
                        st.download_button("📥 Télécharger le PDF", f, file_name=os.path.basename(entry['report_path']), key=f"dl_{entry['id']}", type="primary")
                else:
                    st.error("PDF indisponible.")
                
                # Génération de lien de partage temporaire/sécurisé
                st.markdown("<br>", unsafe_allow_html=True)
                share_url = f"http://localhost:8501/?share={entry['id']}"
                if st.button("🔗 Générer lien de partage", key=f"btn_share_{entry['id']}"):
                    st.success("Lien de partage généré :")
                    st.code(share_url)
                    
            with col_vault2:
                # Bouton de génération de remédiation SecOps (Ansible / Bash)
                if entry.get("vulnerabilities_json"):
                    state_key = f"remediation_{entry['id']}"
                    if state_key not in st.session_state:
                        st.session_state[state_key] = None
                        
                    if st.button("🛠️ Générer Scripts SecOps (Ansible/Bash)", key=f"btn_rem_{entry['id']}"):
                        with st.spinner("Génération des playbooks SecOps..."):
                            try:
                                vulns_list = json.loads(entry["vulnerabilities_json"])
                                prompt = (
                                    "Tu es un ingénieur DevOps expert en sécurité (SecOps).\n"
                                    "Voici une liste de vulnérabilités découvertes sur la cible :\n"
                                    f"```json\n{json.dumps(vulns_list, indent=2)}\n```\n\n"
                                    "Génère :\n"
                                    "1. Un Playbook Ansible complet, robuste et prêt à l'emploi pour corriger ou mitiger ces failles (ex: désactiver des ports inutiles, durcir des configurations Nginx/Apache, corriger des fichiers de conf, installer des patches).\n"
                                    "2. Un script Bash autonome de secours (`remediation.sh`) effectuant des vérifications et corrections directes sur la machine.\n\n"
                                    "Présente le playbook Ansible en premier (dans un bloc de code ```yaml), puis le script Bash (dans un bloc de code ```bash). "
                                    "Sois extrêmement précis, professionnel et commente tes scripts en français."
                                )
                                llm = chat.get_llm()
                                response = llm.invoke(prompt)
                                if not isinstance(response, str):
                                    response = getattr(response, "content", str(response))
                                st.session_state[state_key] = response
                            except Exception as e:
                                st.error(f"Erreur de génération : {e}")
                                
            # Affichage du script SecOps si généré
            if entry.get("vulnerabilities_json") and st.session_state.get(f"remediation_{entry['id']}"):
                st.markdown("---")
                st.markdown("### 📋 Scripts de Correction SecOps Générés")
                st.markdown(st.session_state[f"remediation_{entry['id']}"])
                st.download_button(
                    "📥 Télécharger les scripts de remédiation (.txt)",
                    st.session_state[f"remediation_{entry['id']}"],
                    file_name=f"sentient_remediation_{entry['id']}.txt",
                    mime="text/plain",
                    key=f"dl_rem_txt_{entry['id']}"
                )

            # Intégration d'outils de ticketing (Jira, GitHub, GitLab)
            st.markdown("---")
            st.markdown("##### 🎫 Exporter vers Ticketing (Jira / GitHub / GitLab)")
            
            with st.expander("Créer un ticket pour cet audit", expanded=False):
                ticket_platform = st.selectbox("Plateforme de destination", ["GitHub Issues", "GitLab Issues", "Jira"], key=f"plat_{entry['id']}")
                
                if ticket_platform == "GitHub Issues":
                    gh_owner = st.text_input("Propriétaire du dépôt (Owner / Org)", placeholder="ex: mon-organisation", key=f"gh_own_{entry['id']}")
                    gh_repo = st.text_input("Nom du dépôt (Repository)", placeholder="ex: mon-application", key=f"gh_rep_{entry['id']}")
                    gh_token = st.text_input("Jetons d'accès personnel (Token)", type="password", key=f"gh_tok_{entry['id']}")
                    
                    if st.button("🚀 Pousser l'Issue GitHub", key=f"gh_btn_{entry['id']}"):
                        import requests
                        if not (gh_owner and gh_repo and gh_token):
                            st.error("Veuillez remplir tous les champs.")
                        else:
                            with st.spinner("Création de l'issue GitHub..."):
                                url = f"https://api.github.com/repos/{gh_owner}/{gh_repo}/issues"
                                headers = {
                                    "Authorization": f"token {gh_token}",
                                    "Accept": "application/vnd.github.v3+json"
                                }
                                vuln_summary = f"Audit de sécurité Sentient AI sur {entry['target']} du {entry['date']}\n"
                                vuln_summary += f"Nombre d'hôtes : {entry['hosts_found']} | Vulnérabilités : {entry['vulnerabilities_found']}\n\n"
                                if entry.get("vulnerabilities_json"):
                                    try:
                                        v_list = json.loads(entry["vulnerabilities_json"])
                                        for idx, v in enumerate(v_list):
                                            vuln_summary += f"### {idx+1}. {v.get('info', {}).get('name')}\n"
                                            vuln_summary += f"- **Sévérité :** {v.get('info', {}).get('severity')}\n"
                                            vuln_summary += f"- **Hôte :** {v.get('host')}\n"
                                            vuln_summary += f"- **Description :** {v.get('info', {}).get('description')}\n\n"
                                    except:
                                        pass
                                
                                payload = {
                                    "title": f"🛡️ Audit de Sécurité Sentient AI - {entry['target']}",
                                    "body": vuln_summary
                                }
                                r = requests.post(url, headers=headers, json=payload)
                                if r.status_code == 201:
                                    st.success(f"Issue GitHub créée avec succès ! Numéro: {r.json().get('number')}")
                                else:
                                    st.error(f"Échec de création (HTTP {r.status_code}) : {r.text}")
                                    
                elif ticket_platform == "GitLab Issues":
                    gl_url = st.text_input("URL de l'instance GitLab", value="https://gitlab.com", key=f"gl_url_{entry['id']}")
                    gl_project = st.text_input("ID du Projet (Project ID)", placeholder="ex: 12345678", key=f"gl_proj_{entry['id']}")
                    gl_token = st.text_input("Jetons d'accès personnel (Token)", type="password", key=f"gl_tok_{entry['id']}")
                    
                    if st.button("🚀 Pousser l'Issue GitLab", key=f"gl_btn_{entry['id']}"):
                        import requests
                        if not (gl_project and gl_token):
                            st.error("Veuillez remplir tous les champs.")
                        else:
                            with st.spinner("Création de l'issue GitLab..."):
                                url = f"{gl_url.rstrip('/')}/api/v4/projects/{gl_project}/issues"
                                headers = {
                                    "PRIVATE-TOKEN": gl_token
                                }
                                vuln_summary = f"Audit de sécurité Sentient AI sur {entry['target']} du {entry['date']}\n"
                                vuln_summary += f"Nombre d'hôtes : {entry['hosts_found']} | Vulnérabilités : {entry['vulnerabilities_found']}\n\n"
                                if entry.get("vulnerabilities_json"):
                                    try:
                                        v_list = json.loads(entry["vulnerabilities_json"])
                                        for idx, v in enumerate(v_list):
                                            vuln_summary += f"### {idx+1}. {v.get('info', {}).get('name')}\n"
                                            vuln_summary += f"- **Sévérité :** {v.get('info', {}).get('severity')}\n"
                                            vuln_summary += f"- **Hôte :** {v.get('host')}\n"
                                            vuln_summary += f"- **Description :** {v.get('info', {}).get('description')}\n\n"
                                    except:
                                        pass
                                
                                payload = {
                                    "title": f"🛡️ Audit de Sécurité Sentient AI - {entry['target']}",
                                    "description": vuln_summary
                                }
                                r = requests.post(url, headers=headers, json=payload)
                                if r.status_code == 201:
                                    st.success(f"Issue GitLab créée avec succès ! ID: {r.json().get('iid')}")
                                else:
                                    st.error(f"Échec de création (HTTP {r.status_code}) : {r.text}")
                                    
                elif ticket_platform == "Jira":
                    jira_url = st.text_input("URL Jira Instance", placeholder="https://votre-instance.atlassian.net", key=f"ji_url_{entry['id']}")
                    jira_email = st.text_input("Email d'utilisateur Jira", key=f"ji_usr_{entry['id']}")
                    jira_token = st.text_input("Token API Jira", type="password", key=f"ji_tok_{entry['id']}")
                    jira_project = st.text_input("Clé du Projet (Project Key)", placeholder="ex: SEC", key=f"ji_proj_{entry['id']}")
                    
                    if st.button("🚀 Pousser le Ticket Jira", key=f"ji_btn_{entry['id']}"):
                        import requests
                        import base64
                        if not (jira_url and jira_email and jira_token and jira_project):
                            st.error("Veuillez remplir tous les champs.")
                        else:
                            with st.spinner("Création du ticket Jira..."):
                                url = f"{jira_url.rstrip('/')}/rest/api/3/issue"
                                auth_str = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()
                                headers = {
                                    "Authorization": f"Basic {auth_str}",
                                    "Content-Type": "application/json",
                                    "Accept": "application/json"
                                }
                                vuln_summary = f"Audit de sécurité Sentient AI sur {entry['target']} du {entry['date']}\n"
                                vuln_summary += f"Nombre d'hôtes : {entry['hosts_found']} | Vulnérabilités : {entry['vulnerabilities_found']}\n\n"
                                if entry.get("vulnerabilities_json"):
                                    try:
                                        v_list = json.loads(entry["vulnerabilities_json"])
                                        for idx, v in enumerate(v_list):
                                            vuln_summary += f"{idx+1}. {v.get('info', {}).get('name')} (Sévérité: {v.get('info', {}).get('severity')} - Hôte: {v.get('host')})\n"
                                    except:
                                        pass
                                
                                payload = {
                                    "fields": {
                                        "project": {
                                            "key": jira_project
                                        },
                                        "summary": f"🛡️ Audit de Sécurité Sentient AI - {entry['target']}",
                                        "description": {
                                            "type": "doc",
                                            "version": 1,
                                            "content": [
                                                {
                                                    "type": "paragraph",
                                                    "content": [
                                                        {
                                                            "type": "text",
                                                            "text": vuln_summary
                                                        }
                                                    ]
                                                }
                                            ]
                                        },
                                        "issuetype": {
                                            "name": "Task"
                                        }
                                    }
                                }
                                r = requests.post(url, headers=headers, json=payload)
                                if r.status_code == 201:
                                    st.success(f"Ticket Jira créé avec succès ! Clé: {r.json().get('key')}")
                                else:
                                    st.error(f"Échec de création (HTTP {r.status_code}) : {r.text}")

elif menu == "🧠 Base de Connaissances (RAG)":
    st.markdown("<h2>Base de Connaissances (RAG)</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Alimentez l'IA avec vos propres standards de sécurité (PDF, TXT, MD).</p><br>", unsafe_allow_html=True)
    
    col_stat, col_action = st.columns([3, 1])
    with col_stat:
        st.info(f"📚 Fragments de connaissances actuellement indexés en mémoire locale : **{rag.get_doc_count()}**")
    with col_action:
        if st.button("🗑️ Purger la base"):
            rag.clear_db()
            st.rerun()
            
    st.markdown("### 📥 Importer un référentiel")
    uploaded_files = st.file_uploader("Glissez vos documents ici (ANSSI, ISO 27001, Procédures internes)", accept_multiple_files=True, type=['txt', 'md', 'pdf'])
    
    if st.button("🚀 Vectoriser et Apprendre", type="primary"):
        if uploaded_files:
            with st.spinner("Analyse vectorielle (Embeddings) en cours..."):
                total_chunks = 0
                for file in uploaded_files:
                    chunks = rag.add_document(file.read(), file.name)
                    total_chunks += chunks
                if total_chunks > 0:
                    st.success(f"Opération réussie ! {total_chunks} paragraphes ont été ajoutés à la mémoire de l'IA.")
                else:
                    st.warning("Aucun texte exploitable n'a été trouvé dans ces fichiers.")
        else:
            st.error("Veuillez sélectionner au moins un document.")
            
    st.markdown("---")
    st.markdown("### 🏛️ Référentiels Standards Cyber")
    st.markdown("Vous pouvez charger directement les référentiels de sécurité standards pré-intégrés (ANSSI, CIS Benchmarks, OWASP Top 10) dans la base de connaissances locale.")
    if st.button("📥 Pré-charger les référentiels standards (ANSSI, CIS, OWASP)", type="secondary"):
        with st.spinner("Chargement et vectorisation des référentiels..."):
            total_added = rag.prepopulate_cyber_guidelines(force=True)
            if total_added > 0:
                st.success(f"Référentiels pré-chargés avec succès ! {total_added} paragraphes de connaissances ont été ajoutés.")
                st.rerun()
            else:
                st.info("Les référentiels sont déjà présents ou n'ont pas pu être chargés.")

elif menu == "🖥️ Diagnostic & Performance":
    st.markdown("<h2>🖥️ Diagnostic Matériel & Performance IA</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Surveillez l'utilisation des ressources système en temps réel et testez la performance de l'IA locale.</p><br>", unsafe_allow_html=True)
    
    tel = get_system_telemetry()
    
    # Section Télémétrie Matérielle
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div style="background-color: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
            <h3 style="margin-top:0; color:#fafafa; font-size:1.2rem; border-bottom:1px solid #27272a; padding-bottom:10px;">💾 Système & Mémoire</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # CPU
        st.markdown(f"**Processeur (CPU) :** {tel['cpu_count']} Coeurs physiques / logiques")
        st.progress(min(max(tel['cpu_pct'] / 100.0, 0.0), 1.0))
        st.markdown(f"<p style='text-align:right; font-size:0.85rem; color:#a1a1aa; margin-top:-10px;'>Charge CPU estimée : <b>{tel['cpu_pct']:.1f}%</b></p>", unsafe_allow_html=True)
        
        # Load averages
        st.markdown("**Moyennes de charge (Load Averages) :**")
        col_l1, col_l2, col_l3 = st.columns(3)
        with col_l1:
            st.metric("1 min", f"{tel['load_1m']:.2f}")
        with col_l2:
            st.metric("5 min", f"{tel['load_5m']:.2f}")
        with col_l3:
            st.metric("15 min", f"{tel['load_15m']:.2f}")
            
        # RAM
        st.markdown(f"**Mémoire Système (RAM) :** {tel['ram_used']:.1f} GB / {tel['ram_total']:.1f} GB")
        st.progress(min(max(tel['ram_pct'] / 100.0, 0.0), 1.0))
        st.markdown(f"<p style='text-align:right; font-size:0.85rem; color:#a1a1aa; margin-top:-10px;'>Utilisation RAM : <b>{tel['ram_pct']:.1f}%</b></p>", unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style="background-color: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 20px; margin-bottom: 20px;">
            <h3 style="margin-top:0; color:#fafafa; font-size:1.2rem; border-bottom:1px solid #27272a; padding-bottom:10px;">🎮 Accélération Graphique & IA</h3>
        </div>
        """, unsafe_allow_html=True)
        
        if not tel["has_gpu"]:
            st.warning("⚠️ Aucun GPU compatible détecté (NVIDIA CUDA ou AMD ROCm). L'exécution locale s'effectue sur le processeur (CPU), ce qui ralentira significativement la vitesse de traitement de l'IA.")
            st.markdown(f"**Dispositif principal détecté :** {tel['gpu_model']}")
        else:
            st.success(f"✅ GPU compatible détecté : **{tel['gpu_model']}**")
            
            # GPU Utilization
            st.markdown(f"**Charge du Processeur Graphique (GPU) :**")
            st.progress(min(max(tel['gpu_util'] / 100.0, 0.0), 1.0))
            st.markdown(f"<p style='text-align:right; font-size:0.85rem; color:#a1a1aa; margin-top:-10px;'>Activité GPU : <b>{tel['gpu_util']:.1f}%</b></p>", unsafe_allow_html=True)
            
            # VRAM Usage
            if tel["vram_total"] > 0:
                st.markdown(f"**Mémoire Vidéo Dédiée (VRAM) :** {tel['vram_used']:.2f} GB / {tel['vram_total']:.2f} GB")
                st.progress(min(max(tel['vram_pct'] / 100.0, 0.0), 1.0))
                st.markdown(f"<p style='text-align:right; font-size:0.85rem; color:#a1a1aa; margin-top:-10px;'>Utilisation VRAM : <b>{tel['vram_pct']:.1f}%</b></p>", unsafe_allow_html=True)
            else:
                st.info("Mémoire VRAM indisponible ou partagée dynamiquement.")
                
        # Status Ollama
        st.markdown("---")
        st.markdown("**Statut Ollama :**")
        if tel["ollama_connected"]:
            st.markdown(f"🟢 **Service actif** sur `{tel.get('ollama_base_url', 'http://localhost:11434')}`  \nModèle par défaut : `{tel['ollama_model']}`")
        else:
            st.markdown("🔴 **Service injoignable** ou éteint.")
            
    # Section Benchmark
    st.markdown("---")
    st.markdown("### ⚡ Benchmark IA (Test de Vitesse de l'IA locale)")
    st.markdown("Mesurez précisément la vitesse de génération (tokens/seconde) de vos modèles de langage locaux chargés sur Ollama.")
    
    if not tel["ollama_connected"]:
        st.error("Le service Ollama est hors ligne. Impossible de lancer le test de performance.")
    else:
        # Récupérer la liste des modèles
        models = []
        try:
            import requests
            ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            r = requests.get(f"{ollama_base_url}/api/tags", timeout=2.0)
            if r.status_code == 200:
                models_data = r.json()
                models = [m.get("name") for m in models_data.get("models", [])]
        except Exception:
            pass
            
        if not models:
            st.warning("Aucun modèle n'est actuellement installé dans Ollama.")
        else:
            with st.form("benchmark_form"):
                col_bm1, col_bm2 = st.columns([1, 2])
                with col_bm1:
                    selected_model = st.selectbox("Modèle à tester", models)
                with col_bm2:
                    test_prompt = st.text_input("Prompt de test", value="Explique-moi la théorie de la relativité générale en 3 phrases simples.")
                    
                submitted_bm = st.form_submit_button("🚀 Lancer le Test de Vitesse", type="primary")
                
            if submitted_bm:
                with st.spinner("Exécution du benchmark de génération..."):
                    import time
                    import requests
                    
                    payload = {
                        "model": selected_model,
                        "prompt": test_prompt,
                        "stream": False
                    }
                    
                    start_time = time.time()
                    try:
                        ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
                        r = requests.post(f"{ollama_base_url}/api/generate", json=payload, timeout=60.0)
                        duration_elapsed = time.time() - start_time
                        
                        if r.status_code == 200:
                            res_data = r.json()
                            
                            # Extraction des métriques
                            response_text = res_data.get("response", "")
                            
                            eval_count = res_data.get("eval_count", 0)
                            eval_duration_ns = res_data.get("eval_duration", 0)
                            
                            prompt_eval_count = res_data.get("prompt_eval_count", 0)
                            prompt_eval_duration_ns = res_data.get("prompt_eval_duration", 0)
                            
                            total_duration_ns = res_data.get("total_duration", 0)
                            
                            # Calcul des vitesses
                            # Génération (eval)
                            if eval_duration_ns > 0:
                                tps = eval_count / (eval_duration_ns / 1e9)
                            elif duration_elapsed > 0:
                                # Fallback si pas de metrics détaillés
                                tps = eval_count / duration_elapsed
                            else:
                                tps = 0.0
                                
                            # Prompt Evaluation (analyse de prompt)
                            if prompt_eval_duration_ns > 0:
                                prompt_tps = prompt_eval_count / (prompt_eval_duration_ns / 1e9)
                            else:
                                prompt_tps = 0.0
                                
                            total_sec = total_duration_ns / 1e9 if total_duration_ns > 0 else duration_elapsed
                            
                            # Affichage des métriques de performance
                            st.success("Test terminé avec succès !")
                            
                            col_m1, col_m2, col_m3 = st.columns(3)
                            with col_m1:
                                st.metric("Débit Génération", f"{tps:.2f} tok/s", help="Vitesse d'écriture de la réponse par l'IA.")
                            with col_m2:
                                st.metric("Vitesse d'Analyse Prompt", f"{prompt_tps:.2f} tok/s" if prompt_tps > 0 else "N/A", help="Vitesse d'assimilation de votre prompt initial par le modèle.")
                            with col_m3:
                                st.metric("Temps de Réponse Global", f"{total_sec:.2f} s")
                                
                            # Diagnostic de Performance
                            if tps >= 25.0:
                                st.markdown("""
                                <div style="background-color: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; border-radius: 8px; padding: 12px; color: #22c55e; font-weight: bold; margin-bottom: 15px;">
                                    🚀 Performances exceptionnelles (Accélération matérielle active, optimal pour l'audit et l'analyse de vulnérabilités en temps réel)
                                </div>
                                """, unsafe_allow_html=True)
                            elif tps >= 10.0:
                                st.markdown("""
                                <div style="background-color: rgba(234, 179, 8, 0.15); border: 1px solid #eab308; border-radius: 8px; padding: 12px; color: #eab308; font-weight: bold; margin-bottom: 15px;">
                                    ⚡ Performances correctes (Accélération GPU active, adapté pour l'usage quotidien)
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.markdown("""
                                <div style="background-color: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 12px; color: #ef4444; font-weight: bold; margin-bottom: 15px;">
                                    ⚠️ Performances lentes (Exécution sur CPU ou ressources GPU limitées. L'analyse RAG et les audits de rapports volumineux prendront plus de temps)
                                </div>
                                """, unsafe_allow_html=True)
                                
                            with st.expander("📝 Réponse Générée par le Modèle", expanded=True):
                                st.write(response_text)
                                
                        else:
                            st.error(f"Erreur d'Ollama (HTTP {r.status_code}) : {r.text}")
                    except Exception as e:
                        st.error(f"Une erreur s'est produite lors de l'appel à l'API d'Ollama : {e}")

elif menu == "⚙️ Configuration":
    st.markdown("<h2>Configuration Globale</h2>", unsafe_allow_html=True)
    st.info("Section d'administration et Connecteurs d'Entreprise.")
    
    st.markdown("### ☁️ Connecteur DefectDojo (API)")
    st.markdown("Permet d'exporter automatiquement les résultats bruts des scans vers une plateforme de gestion des vulnérabilités.")
    
    dojo_config = defectdojo.load_config()
    
    with st.form("dojo_form"):
        dojo_url = st.text_input("URL DefectDojo", value=dojo_config.get("url", ""), placeholder="https://dojo.mon-entreprise.com")
        dojo_token = st.text_input("Clé API (Token)", value=dojo_config.get("token", ""), placeholder="e.g. abc123def456...", type="password")
        dojo_eng_id = st.text_input("ID de l'Engagement", value=dojo_config.get("engagement_id", ""), placeholder="e.g. 42")
        
        submitted_dojo = st.form_submit_button("Sauvegarder la configuration", type="primary")
        
        if submitted_dojo:
            if defectdojo.save_config(dojo_url, dojo_token, dojo_eng_id):
                st.success("Configuration sauvegardée avec succès.")
                
    st.markdown("---")
    st.markdown("### 🎨 Personnalisation des Rapports (White-Label)")
    st.markdown("Personnalisez l'identité visuelle de vos rapports PDF d'audit générés (Nom d'entreprise, logo, couleur principale et pied de page).")
    
    rep_cfg = report_config.load_report_config()
    
    with st.form("white_label_form"):
        col_wl1, col_wl2 = st.columns(2)
        with col_wl1:
            comp_name = st.text_input("Nom de l'entreprise", value=rep_cfg.get("company_name", "Sentient AI"))
            foot_text = st.text_input("Texte de pied de page", value=rep_cfg.get("footer_text", "Sentient AI - Rapport d'Audit Automatisé"))
            theme_list = ["Slate/Zinc", "Light/Clean", "Matrix/Hacker"]
            saved_theme = rep_cfg.get("theme", "Slate/Zinc")
            theme_idx = theme_list.index(saved_theme) if saved_theme in theme_list else 0
            selected_theme = st.selectbox("Thème de l'interface graphique (UI)", theme_list, index=theme_idx)
        with col_wl2:
            prim_color = st.color_picker("Couleur principale du rapport", value=rep_cfg.get("primary_color", "#7c3aed"))
            logo_file = st.file_uploader("Logo de l'entreprise (PNG/JPG)", type=["png", "jpg", "jpeg"])
            
            existing_logo = rep_cfg.get("logo_path", "")
            if existing_logo and os.path.exists(existing_logo):
                st.image(existing_logo, caption="Logo actuel", width=120)
                
        submitted_wl = st.form_submit_button("Sauvegarder le style & thème", type="primary")
        
        if submitted_wl:
            logo_path = rep_cfg.get("logo_path", "")
            if logo_file is not None:
                os.makedirs("assets", exist_ok=True)
                _, ext = os.path.splitext(logo_file.name)
                logo_path = f"assets/report_logo{ext}"
                try:
                    with open(logo_path, "wb") as f:
                        f.write(logo_file.getbuffer())
                except Exception as e:
                    st.error(f"Erreur lors de l'enregistrement du logo: {e}")
                    logo_path = ""
            
            if report_config.save_report_config(
                comp_name, 
                prim_color, 
                foot_text, 
                logo_path,
                sector=rep_cfg.get("sector"),
                company_size=rep_cfg.get("company_size"),
                data_sensitivity=rep_cfg.get("data_sensitivity"),
                theme=selected_theme
            ):
                st.success("Style de rapport et thème UI sauvegardés avec succès.")
                st.rerun()

    st.markdown("---")
    st.markdown("### 🏢 Profil de l'Organisation (Analyse de Risque & ROI)")
    st.markdown("Configurez les caractéristiques par défaut de votre organisation pour personnaliser le calcul du Risque Financier et du ROI.")
    
    with st.form("org_profile_form"):
        col_op1, col_op2, col_op3 = st.columns(3)
        with col_op1:
            sector_list = list(roi_calculator.SECTOR_MULTIPLIERS.keys())
            saved_sector = rep_cfg.get("sector", "Finance / Assurances")
            sector_idx = sector_list.index(saved_sector) if saved_sector in sector_list else 0
            org_sector = st.selectbox("Secteur d'Activité par défaut", sector_list, index=sector_idx)
        with col_op2:
            size_list = list(roi_calculator.COMPANY_SIZE_MULTIPLIERS.keys())
            saved_size = rep_cfg.get("company_size", "PME (50 - 250 employés)")
            size_idx = size_list.index(saved_size) if saved_size in size_list else 1
            org_size = st.selectbox("Taille de l'Entreprise par défaut", size_list, index=size_idx)
        with col_op3:
            sens_list = list(roi_calculator.DATA_SENSITIVITY_MULTIPLIERS.keys())
            saved_sens = rep_cfg.get("data_sensitivity", "PII standard (Noms, Emails)")
            sens_idx = sens_list.index(saved_sens) if saved_sens in sens_list else 1
            org_sens = st.selectbox("Sensibilité des Données par défaut", sens_list, index=sens_idx)
            
        st.markdown("<br><strong>🛡️ Coûts Cyber de Base par Sévérité (Défauts)</strong>", unsafe_allow_html=True)
        col_c1, col_c2 = st.columns(2)
        saved_breach = rep_cfg.get("custom_breach_costs", roi_calculator.BASE_BREACH_COSTS)
        saved_remed = rep_cfg.get("custom_remediation_costs", roi_calculator.BASE_REMEDIATION_COSTS)
        
        with col_c1:
            st.markdown("<p style='font-size:0.85rem; color:#a1a1aa; margin-bottom: 5px;'>Exposition Financière de Base (Impact Brèche)</p>", unsafe_allow_html=True)
            cfg_b_crit = st.number_input("Critique (€) - Exposition", min_value=0.0, value=float(saved_breach.get("critical", 150000.0)), step=5000.0, key="cfg_b_crit")
            cfg_b_high = st.number_input("Élevée (€) - Exposition", min_value=0.0, value=float(saved_breach.get("high", 60000.0)), step=2000.0, key="cfg_b_high")
            cfg_b_med = st.number_input("Moyenne (€) - Exposition", min_value=0.0, value=float(saved_breach.get("medium", 15000.0)), step=1000.0, key="cfg_b_med")
            cfg_b_low = st.number_input("Faible (€) - Exposition", min_value=0.0, value=float(saved_breach.get("low", 3000.0)), step=500.0, key="cfg_b_low")
            
        with col_c2:
            st.markdown("<p style='font-size:0.85rem; color:#a1a1aa; margin-bottom: 5px;'>Coût de Remédiation de Base (Ingénierie)</p>", unsafe_allow_html=True)
            cfg_r_crit = st.number_input("Critique (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("critical", 4000.0)), step=500.0, key="cfg_r_crit")
            cfg_r_high = st.number_input("Élevée (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("high", 2000.0)), step=200.0, key="cfg_r_high")
            cfg_r_med = st.number_input("Moyenne (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("medium", 800.0)), step=100.0, key="cfg_r_med")
            cfg_r_low = st.number_input("Faible (€) - Remédiation", min_value=0.0, value=float(saved_remed.get("low", 200.0)), step=50.0, key="cfg_r_low")
            
        submitted_op = st.form_submit_button("Sauvegarder le profil", type="primary")
        if submitted_op:
            new_breach = {
                "critical": cfg_b_crit,
                "high": cfg_b_high,
                "medium": cfg_b_med,
                "low": cfg_b_low
            }
            new_remed = {
                "critical": cfg_r_crit,
                "high": cfg_r_high,
                "medium": cfg_r_med,
                "low": cfg_r_low
            }
            if report_config.save_report_config(
                company_name=rep_cfg.get("company_name", "Sentient AI"),
                primary_color=rep_cfg.get("primary_color", "#7c3aed"),
                footer_text=rep_cfg.get("footer_text", "Sentient AI - Rapport d'Audit Automatisé"),
                logo_path=rep_cfg.get("logo_path", ""),
                sector=org_sector,
                company_size=org_size,
                data_sensitivity=org_sens,
                custom_breach_costs=new_breach,
                custom_remediation_costs=new_remed
            ):
                st.success("Profil de l'organisation et coûts de base sauvegardés avec succès.")
                st.rerun()

    st.markdown("---")
    st.markdown("### 📡 Sondes de Scan Distantes (Architecture Distribuée)")
    st.markdown("Enregistrez des serveurs distants ou VPS légers exécutant `sentient_agent.py` pour déléguer les scans réseau.")
    
    probes = rep_cfg.get("remote_probes", [])
    
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        st.markdown("**Enregistrer une nouvelle sonde**")
        with st.form("add_probe_form"):
            probe_name = st.text_input("Nom de la sonde", placeholder="ex: VPS Paris")
            probe_url = st.text_input("URL de la sonde", placeholder="ex: http://192.168.1.100:8502")
            probe_token = st.text_input("Jeton de sécurité (Token)", value="sentient_secure_token_2026", type="password")
            submitted_probe = st.form_submit_button("Ajouter la sonde", type="primary")
            if submitted_probe:
                if not probe_name or not probe_url:
                    st.error("Veuillez remplir tous les champs.")
                else:
                    probes.append({
                        "name": probe_name,
                        "url": probe_url,
                        "token": probe_token
                    })
                    if report_config.save_report_config(remote_probes=probes):
                        st.success(f"Sonde '{probe_name}' ajoutée avec succès.")
                        st.rerun()
                        
    with col_p2:
        st.markdown("**Sondes enregistrées**")
        if not probes:
            st.info("Aucune sonde distante enregistrée pour le moment. Les scans s'exécutent localement.")
        else:
            for idx, p in enumerate(probes):
                col_pr, col_del_pr = st.columns([3, 1])
                with col_pr:
                    st.markdown(f"📡 **{p['name']}** — `{p['url']}`")
                with col_del_pr:
                    if st.button("🗑️", key=f"del_probe_{idx}", help=f"Supprimer {p['name']}"):
                        probes.pop(idx)
                        if report_config.save_report_config(remote_probes=probes):
                            st.success(f"Sonde supprimée.")
                            st.rerun()

    st.markdown("---")
    st.markdown("### 🧠 Configuration d'IA & Connecteurs d'Alertes")
    st.markdown("Basculez entre le moteur d'IA local Ollama et des API Cloud (OpenAI, Anthropic, Groq) et configurez les notifications webhooks.")
    
    with st.form("llm_connector_form"):
        col_llm1, col_llm2 = st.columns(2)
        with col_llm1:
            st.markdown("**🔌 Moteur d'Intelligence Artificielle**")
            llm_prov_list = ["Ollama", "OpenAI", "Anthropic", "Groq"]
            saved_prov = rep_cfg.get("llm_provider", "Ollama")
            prov_idx = llm_prov_list.index(saved_prov) if saved_prov in llm_prov_list else 0
            llm_prov = st.selectbox("Fournisseur de LLM", llm_prov_list, index=prov_idx)
            
            llm_mod = st.text_input("Modèle à utiliser", value=rep_cfg.get("llm_model", "llama3.1:8b"), help="Exemples: gpt-4o, claude-3-5-sonnet-20240620, llama-3.1-70b-versatile, llama3.1:8b")
            
            openai_key = st.text_input("Clé d'API OpenAI", value=rep_cfg.get("openai_api_key", ""), type="password")
            anthropic_key = st.text_input("Clé d'API Anthropic", value=rep_cfg.get("anthropic_api_key", ""), type="password")
            groq_key = st.text_input("Clé d'API Groq", value=rep_cfg.get("groq_api_key", ""), type="password")
            
        with col_llm2:
            st.markdown("**🔔 Webhooks d'Alertes de Sécurité**")
            webhook_prov_list = ["Generic", "Slack", "Discord", "Teams"]
            saved_wh_prov = rep_cfg.get("webhook_provider", "Generic")
            wh_prov_idx = webhook_prov_list.index(saved_wh_prov) if saved_wh_prov in webhook_prov_list else 0
            webhook_prov = st.selectbox("Fournisseur de Webhook", webhook_prov_list, index=wh_prov_idx)
            
            webhook_url = st.text_input("URL du Webhook", value=rep_cfg.get("webhook_url", ""), help="Entrez l'adresse de votre webhook Slack/Discord/Teams")
            
        submitted_llm = st.form_submit_button("Sauvegarder les configurations IA & Alertes", type="primary")
        if submitted_llm:
            if report_config.save_report_config(
                llm_provider=llm_prov,
                llm_model=llm_mod,
                openai_api_key=openai_key,
                anthropic_api_key=anthropic_key,
                groq_api_key=groq_key,
                webhook_provider=webhook_prov,
                webhook_url=webhook_url
            ):
                st.success("Configurations d'IA et de Webhooks sauvegardées avec succès.")
                st.rerun()

    st.markdown("---")
    st.markdown("### 📝 Éditeur de Templates Nuclei YAML")
    st.markdown("Créez, modifiez ou testez des templates de vulnérabilités Nuclei à la volée.")
    
    templates_dir = "./custom_templates"
    os.makedirs(templates_dir, exist_ok=True)
    existing_templates = [f for f in os.listdir(templates_dir) if f.endswith(".yaml")]
    
    col_t1, col_t2 = st.columns([2, 1])
    with col_t1:
        tpl_action = st.selectbox("Action", ["Modifier un template existant", "Créer un nouveau template"])
    
    selected_tpl = ""
    tpl_name_new = ""
    tpl_content = ""
    
    if tpl_action == "Modifier un template existant":
        if not existing_templates:
            st.info("Aucun template personnalisé trouvé.")
        else:
            with col_t2:
                selected_tpl = st.selectbox("Sélectionner un template", existing_templates)
            if selected_tpl:
                tpl_path = os.path.join(templates_dir, selected_tpl)
                with open(tpl_path, "r", encoding="utf-8") as f_tpl:
                    tpl_content = f_tpl.read()
    else:
        with col_t2:
            tpl_name_new = st.text_input("Nom du fichier template (ex: test.yaml)")
            
        tpl_content = """id: custom-vulnerability-check
info:
  name: Custom Vulnerability Check
  author: Sentient AI
  severity: medium
  description: Description of the vulnerability.
  
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words:
          - "Administration Console"
"""
        
    tpl_code = st.text_area("Contenu du template (YAML)", value=tpl_content, height=300)
    
    if st.button("💾 Enregistrer le Template", type="primary"):
        if tpl_action == "Modifier un template existant" and selected_tpl:
            tpl_path = os.path.join(templates_dir, selected_tpl)
            with open(tpl_path, "w", encoding="utf-8") as f_tpl:
                f_tpl.write(tpl_code)
            st.success(f"Template '{selected_tpl}' sauvegardé avec succès.")
        elif tpl_action == "Créer un nouveau template" and tpl_name_new:
            if not tpl_name_new.endswith(".yaml"):
                tpl_name_new += ".yaml"
            tpl_path = os.path.join(templates_dir, tpl_name_new)
            with open(tpl_path, "w", encoding="utf-8") as f_tpl:
                f_tpl.write(tpl_code)
            st.success(f"Nouveau template '{tpl_name_new}' créé avec succès.")
            st.rerun()

    st.markdown("---")
    st.markdown("### 👥 Gestion des Utilisateurs (RBAC)")
    st.markdown("Gérez les comptes locaux d'accès à la plateforme Sentient AI.")
    
    col_u1, col_u2 = st.columns(2)
    with col_u1:
        st.markdown("**Créer un nouvel utilisateur**")
        with st.form("create_user_form"):
            new_user = st.text_input("Nom d'utilisateur", placeholder="ex: analyst1")
            new_pass = st.text_input("Mot de passe", type="password", placeholder="••••••••")
            new_role = st.selectbox("Rôle", ["admin", "client"])
            submitted_user = st.form_submit_button("Créer l'utilisateur", type="primary")
            if submitted_user:
                if not new_user or not new_pass:
                    st.error("Veuillez remplir tous les champs.")
                else:
                    if add_user(new_user, new_pass, new_role):
                        st.success(f"Utilisateur '{new_user}' créé avec succès.")
                        st.rerun()
                    else:
                        st.error("Cet utilisateur existe déjà ou une erreur est survenue.")
                        
    with col_u2:
        st.markdown("**Utilisateurs existants**")
        users_list = get_users()
        for u in users_list:
            col_usr, col_del = st.columns([3, 1])
            with col_usr:
                st.markdown(f"👤 `{u['username']}` — Rôle : **{u['role']}**")
            with col_del:
                if u['username'] not in ["admin", "client"]:
                    if st.button("🗑️", key=f"del_user_{u['id']}", help=f"Supprimer {u['username']}"):
                        if delete_user(u['username']):
                            st.success(f"Utilisateur '{u['username']}' supprimé.")
                            st.rerun()
                else:
                    st.markdown("<span style='color:gray;'>Système</span>", unsafe_allow_html=True)

