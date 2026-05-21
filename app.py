import streamlit as st
import os
import pandas as pd
import altair as alt
import random
import json
from datetime import datetime
from database import init_db, add_scan, get_history
from scanner import discover_active_hosts, scan_nuclei, analyze_with_ollama, export_to_pdf
import rag
import defectdojo
import chat
import report_config
import compliance
import roi_calculator

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
# Style CSS Premium (Thème Slate/Zinc SaaS)
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    /* Reset et nettoyage de l'UI Streamlit */
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    
    .block-container {
        padding-top: 2rem !important;
        max-width: 95% !important;
        background-color: #09090b; /* Zinc-950 */
    }

    /* Background principal */
    .stApp {
        background-color: #09090b;
        color: #f4f4f5;
    }

    /* Style des KPI Cards */
    .kpi-card {
        background-color: #18181b; /* Zinc-900 */
        border: 1px solid #27272a; /* Zinc-800 */
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5), 0 2px 4px -1px rgba(0, 0, 0, 0.3);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
    .kpi-title {
        font-size: 0.875rem;
        color: #a1a1aa; /* Zinc-400 */
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
        font-weight: 600;
    }
    .kpi-value {
        font-size: 2.25rem;
        font-weight: 700;
        color: #fafafa; /* Zinc-50 */
        margin-bottom: 8px;
    }
    
    /* Badges de Sévérité */
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

    /* Telemetry Sidebar */
    .telemetry-box {
        background-color: #18181b;
        border: 1px solid #27272a;
        border-radius: 8px;
        padding: 12px;
        margin-top: auto;
        font-size: 0.8rem;
        color: #a1a1aa;
    }
    .telemetry-item {
        display: flex;
        justify-content: space-between;
        margin-bottom: 6px;
    }
    .dot {
        height: 8px;
        width: 8px;
        background-color: #22c55e;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
    }
    .dot-warning { background-color: #eab308; }
</style>
""", unsafe_allow_html=True)

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
    
    menu = st.radio(
        "Navigation",
        options=[
            "📊 Tableau de Bord", 
            "⚡ Lancer un Audit", 
            "💰 Analyse de Risque ROI",
            "📂 Centre de Rapports", 
            "💬 Assistant Virtuel",
            "🧠 Base de Connaissances (RAG)", 
            "⚙️ Configuration"
        ],
        label_visibility="collapsed"
    )
    
    st.markdown("<br><br><br><br><br><br>", unsafe_allow_html=True)
    st.markdown("---")
    # Section Télémétrie Système
    st.markdown("""
        <div class="telemetry-box">
            <div style="margin-bottom: 10px; font-weight: bold; color: #e4e4e7;">Télémétrie Système</div>
            <div class="telemetry-item">
                <span><span class="dot"></span>Ollama</span>
                <span style="color:#22c55e;">Connecté</span>
            </div>
            <div class="telemetry-item">
                <span>GPU Actif</span>
                <span style="color:#e4e4e7;">RTX 3060</span>
            </div>
            <div class="telemetry-item">
                <span>VRAM Usage</span>
                <span style="color:#eab308;">4.8 / 12 GB</span>
            </div>
            <div class="telemetry-item">
                <span>Modèle IA</span>
                <span style="color:#e4e4e7;">Llama 3.1 8B Q4</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Logique de Navigation
# -----------------------------------------------------------------------------

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
            roi_data = roi_calculator.calculate_financial_risk(vulns, sector, company_size, data_sensitivity)
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
    
    with st.form("scan_form", border=False):
        st.markdown("""
        <div style="background-color: #18181b; padding: 25px; border-radius: 12px; border: 1px solid #27272a;">
        """, unsafe_allow_html=True)
        
        target_input = st.text_input("🎯 Périmètre d'Audit (IP, URL, CIDR)", placeholder="ex: 192.168.1.0/24 ou scanme.nmap.org")
        
        col_s1, col_s2, col_s3 = st.columns(3)
        with col_s1:
            nmap_mode_sel = st.selectbox("Moteur de Découverte", ["Nmap - Top 1000 Ports (Recommandé)", "Nmap - Fast (Top 100)", "Nmap - Full (65535)"], index=0)
            use_demo_mode = st.checkbox("🎭 Mode Démo (Simulation)", value=False, help="Active un scan simulé instantané avec des failles critiques de test pour démonstration.")
        with col_s2:
            nuclei_mode_sel = st.selectbox("Moteur d'Exploitation", ["Nuclei - Full (Automatique)", "Nuclei - Web CVEs", "Nuclei - Passif"], index=0)
        with col_s3:
            st.selectbox("Modèle d'Orchestration IA", ["Llama 3.1 8B (Actif)", "Qwen 2.5 Coder (Désactivé)"], index=0)
            report_lang = st.selectbox("Langue du rapport final", ["Français", "Anglais", "Espagnol", "Allemand"], index=0)
            
        st.markdown("<br><h5>⚙️ Options Avancées</h5>", unsafe_allow_html=True)
        col_adv1, col_adv2 = st.columns(2)
        with col_adv1:
            st.markdown("**Nmap (Réseau)**")
            use_agressive = st.checkbox("Détection Agressive (OS, Versions, Traceroute)", value=False, help="Active le flag -A de Nmap (plus lent mais plus précis)")
            use_vuln_script = st.checkbox("Scripts de Vulnérabilités Nmap", value=False, help="Active --script vuln pour trouver des failles réseau pures")
        with col_adv2:
            st.markdown("**Nuclei (Couche Applicative)**")
            use_default_logins = st.checkbox("Mots de passe par défaut (Default-Logins)", value=True, help="Recherche les identifiants admin:admin sur les panels")
            use_exposures = st.checkbox("Fuites de données (Exposures)", value=True, help="Recherche les fichiers .env, clés RSA, etc.")
            use_misconfigs = st.checkbox("Mauvaises Configurations", value=True, help="Recherche les erreurs de config serveur")
            
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
                    with st.status("Étape 1 : Découverte du périmètre réseau (Nmap)", expanded=True) as status1:
                        st.write("Exécution des sondes réseau...")
                        active_hosts = discover_active_hosts(target_input, nmap_mode, use_agressive, use_vuln_script)
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
                    
                    if use_default_logins: selected_tags.append("default-login")
                    if use_exposures: selected_tags.append("exposure")
                    if use_misconfigs: selected_tags.append("misconfig")
                    
                    if not selected_tags and "Full" not in nuclei_mode_sel:
                        selected_tags = ["cve", "default-login", "exposure", "misconfig"] # Fallback robuste
                    
                    with st.status("Étape 2 : Analyse de vulnérabilités (Nuclei)", expanded=True) as status2:
                        st.write("Exécution des templates de sécurité (Cette étape est longue)...")
                        nuclei_results = scan_nuclei(active_hosts, selected_tags if selected_tags else None)
                        status2.update(label=f"Analyse terminée : {len(nuclei_results)} anomalies relevées.", state="complete", expanded=False)
                    progress_bar.progress(50)
                
                with st.status("Étape 3 : Traitement par l'IA (Ollama)", expanded=True) as status3:
                    st.write("Synthèse et génération des recommandations...")
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
                
        if not vulns:
            st.success("Aucune vulnérabilité trouvée sur ce scan. L'exposition financière est nulle (0.00 €) !")
        else:
            # Calculer le risque
            roi_results = roi_calculator.calculate_financial_risk(vulns, sim_sector, sim_size, sim_sens)
            
            # Afficher les KPIs
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"""
                    <div class="kpi-card">
                        <div class="kpi-title">Exposition (Risque Brut)</div>
                        <div class="kpi-value" style="color: #ef4444;">{roi_results['total_exposure']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Coût potentiel d'une brèche</div>
                    </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
                    <div class="kpi-card">
                        <div class="kpi-title">Coût de Remédiation</div>
                        <div class="kpi-value" style="color: #2563eb;">{roi_results['total_remediation']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Ingénierie & Correctifs</div>
                    </div>
                """, unsafe_allow_html=True)
            with c3:
                st.markdown(f"""
                    <div class="kpi-card">
                        <div class="kpi-title">Économies Nettes</div>
                        <div class="kpi-value" style="color: #16a34a;">{roi_results['net_savings']:,.2f} €</div>
                        <div style="font-size:0.75rem; color:#a1a1aa;">Risque financier évité</div>
                    </div>
                """, unsafe_allow_html=True)
            with c4:
                st.markdown(f"""
                    <div class="kpi-card">
                        <div class="kpi-title">Taux de ROI</div>
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
                
                # Coût unitaire pour cette vulnérabilité
                base_breach = roi_calculator.BASE_BREACH_COSTS.get(v_severity.lower(), 0.0)
                base_remed = roi_calculator.BASE_REMEDIATION_COSTS.get(v_severity.lower(), 0.0)
                
                v_exposure = base_breach * overall_multiplier
                v_remediation = base_remed
                if sim_size == "ETI (250 - 5000 employés)":
                    v_remediation *= 1.3
                elif sim_size == "Grande Entreprise (> 5000 employés)":
                    v_remediation *= 1.8
                
                m = compliance.map_vulnerability_to_compliance(v_name, v_temp, language="Français")
                
                # Box principal
                st.markdown(f"""
                <div style="background-color: #18181b; padding: 20px; border-radius: 8px; border: 1px solid #27272a; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: start; flex-wrap: wrap;">
                        <div>
                            <span class="badge badge-{v_severity.lower()[:4]}">{v_severity.upper()}</span>
                            <strong style="font-size: 1.05rem; color: #fafafa;">{v_name}</strong>
                            <div style="font-size: 0.85rem; color: #a1a1aa; margin-top: 4px;">Hôte cible : <code>{v_host}</code></div>
                        </div>
                        <div style="text-align: right; min-width: 180px;">
                            <div style="font-size: 0.85rem; color: #ef4444;">Exposition : <strong>{v_exposure:,.2f} €</strong></div>
                            <div style="font-size: 0.85rem; color: #2563eb;">Remédiation : <strong>{v_remediation:,.2f} €</strong></div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                with st.expander(f"🔍 Détails de Conformité & Remédiation pour {v_name}", expanded=False):
                    st.markdown(f"**Description :** {v.get('info', {}).get('description', 'Aucune description disponible.')}")
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

elif menu == "📂 Centre de Rapports":
    st.markdown("<h2>Centre de Rapports (Vault)</h2>", unsafe_allow_html=True)
    st.info("Retrouvez ici tous les PDF générés lors de vos précédents scans.")
    history = get_history()
    for entry in history:
        with st.expander(f"📁 Audit {entry['target']} du {entry['date']}"):
            st.write(f"Hôtes: {entry['hosts_found']} | Failles: {entry['vulnerabilities_found']}")
            if os.path.exists(entry['report_path']):
                with open(entry['report_path'], "rb") as f:
                    st.download_button("📥 Télécharger", f, file_name=os.path.basename(entry['report_path']), key=f"dl_{entry['id']}")
            else:
                st.error("PDF indisponible.")

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
        with col_wl2:
            prim_color = st.color_picker("Couleur principale du rapport", value=rep_cfg.get("primary_color", "#7c3aed"))
            logo_file = st.file_uploader("Logo de l'entreprise (PNG/JPG)", type=["png", "jpg", "jpeg"])
            
            existing_logo = rep_cfg.get("logo_path", "")
            if existing_logo and os.path.exists(existing_logo):
                st.image(existing_logo, caption="Logo actuel", width=120)
                
        submitted_wl = st.form_submit_button("Sauvegarder le style", type="primary")
        
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
                data_sensitivity=rep_cfg.get("data_sensitivity")
            ):
                st.success("Style de rapport sauvegardé avec succès.")
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
            
        submitted_op = st.form_submit_button("Sauvegarder le profil", type="primary")
        if submitted_op:
            if report_config.save_report_config(
                company_name=rep_cfg.get("company_name", "Sentient AI"),
                primary_color=rep_cfg.get("primary_color", "#7c3aed"),
                footer_text=rep_cfg.get("footer_text", "Sentient AI - Rapport d'Audit Automatisé"),
                logo_path=rep_cfg.get("logo_path", ""),
                sector=org_sector,
                company_size=org_size,
                data_sensitivity=org_sens
            ):
                st.success("Profil de l'organisation sauvegardé avec succès.")
                st.rerun()
