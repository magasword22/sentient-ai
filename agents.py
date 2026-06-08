import json
import ast
import warnings
import os

# Suppress Pydantic v1/v2 mixing warnings from CrewAI executor
warnings.filterwarnings("ignore", category=UserWarning, message=".*Mixing V1 models and V2 models.*")

# Polyfill pour Python 3.14 (corrige docstring-parser utilisé par crewai/instructor)
if not hasattr(ast, 'NameConstant'):
    ast.NameConstant = ast.Constant
if not hasattr(ast, 'Num'):
    ast.Num = ast.Constant
if not hasattr(ast, 'Str'):
    ast.Str = ast.Constant

from crewai import Agent, Task, Crew, Process
from langchain_community.llms import Ollama
from langchain.tools import tool
try:
    from ddgs import DDGS
except ImportError:
    pass  # We will handle it if ddgs is not installed

@tool("duckduckgo_search")
def duckduckgo_search(query: str) -> str:
    """Outil de recherche web. Utile pour chercher des PoC ou des exploits sur internet. Entrée: requête textuelle."""
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=2))
            if results:
                return "\n".join([f"- {r['title']}: {r['body']}" for r in results])
            return "Aucun résultat pertinent trouvé."
    except Exception as e:
        return f"Erreur de recherche: {str(e)}"

# Initialisation de l'outil de recherche Web (Custom)
search_tool = duckduckgo_search

# Configuration du LLM Local via Langchain (Ollama)
local_llm = Ollama(
    model="llama3.1:8b",
    base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
)

def get_configured_llm(cfg=None):
    """
    Instancie et retourne le LLM configuré (Ollama, OpenAI, Anthropic, ou Groq).
    """
    import os
    if cfg is None:
        import report_config
        cfg = report_config.load_report_config()
        
    provider = cfg.get("llm_provider", "Ollama")
    model = cfg.get("llm_model", "llama3.1:8b")
    
    if provider == "OpenAI":
        from langchain_openai import ChatOpenAI
        api_key = cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
        return ChatOpenAI(model=model, openai_api_key=api_key)
    elif provider == "Anthropic":
        api_key = cfg.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        try:
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model, anthropic_api_key=api_key)
        except ImportError:
            from langchain_community.chat_models import ChatAnthropic
            return ChatAnthropic(model_name=model, anthropic_api_key=api_key)
    elif provider == "Groq":
        from langchain_openai import ChatOpenAI
        api_key = cfg.get("groq_api_key") or os.environ.get("GROQ_API_KEY")
        return ChatOpenAI(
            model=model, 
            openai_api_key=api_key, 
            openai_api_base="https://api.groq.com/openai/v1"
        )
    else:
        # Ollama (défaut)
        from langchain_community.llms import Ollama
        ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        return Ollama(
            model=model,
            base_url=ollama_base_url
        )

def run_cyber_crew(target_desc, nuclei_results, rag_context, language="Français"):
    """
    Orchestre une équipe d'agents CrewAI pour analyser et rédiger le rapport.
    Cette fonction remplace l'ancien appel direct et simpliste à Ollama.
    """
    if not nuclei_results:
        lang_lower = language.lower()
        if "anglais" in lang_lower or "english" in lang_lower:
            return f"# Vulnerability Assessment Report\n\nTargets: {target_desc}\n\n## Executive Summary\n\nNo vulnerabilities were detected by the scanner on these targets during this surface scan."
        elif "espagnol" in lang_lower or "spanish" in lang_lower:
            return f"# Informe de Evaluación de Vulnerabilidades\n\nObjetivos: {target_desc}\n\n## Resumen Ejecutivo\n\nNo se detectaron vulnerabilidades por el escáner en estos objetivos durante esta exploración de superficie."
        elif "allemand" in lang_lower or "german" in lang_lower:
            return f"# Schwachstellenbewertungsbericht\n\nZiele: {target_desc}\n\n## Zusammenfassung\n\nWährend dieses Oberflächenscans wurden vom Scanner keine Schwachstellen auf diesen Zielen festgestellt."
        else:
            return f"# Rapport d'Évaluation de Vulnérabilités\n\nCibles : {target_desc}\n\n## Résumé Exécutif\n\nAucune vulnérabilité n'a été détectée par le scanner sur ces cibles lors de ce test de surface."

    json_data_str = json.dumps(nuclei_results, indent=2)

    # ---------------------------------------------------------
    # COMPLIANCE MAP & FINANCIAL RISK CALCULATION
    # ---------------------------------------------------------
    import compliance
    import roi_calculator
    import report_config
    
    # Charger le profil de l'organisation
    rep_cfg = report_config.load_report_config()
    sector = rep_cfg.get("sector", "Finance / Assurances")
    company_size = rep_cfg.get("company_size", "PME (50 - 250 employés)")
    data_sensitivity = rep_cfg.get("data_sensitivity", "PII standard (Noms, Emails)")
    custom_breach = rep_cfg.get("custom_breach_costs")
    custom_remed = rep_cfg.get("custom_remediation_costs")
    
    # Résolution dynamique de l'IA active
    active_llm = get_configured_llm(rep_cfg)
    
    # Calculer le ROI et risque financier
    roi_data = roi_calculator.calculate_financial_risk(
        nuclei_results, 
        sector, 
        company_size, 
        data_sensitivity,
        custom_breach_costs=custom_breach,
        custom_remediation_costs=custom_remed
    )
    
    # Générer le contexte de conformité réglementaire
    compliance_items = []
    for v in nuclei_results:
        v_name = v.get("info", {}).get("name", "")
        v_temp = v.get("template-id", "")
        m = compliance.map_vulnerability_to_compliance(v_name, v_temp, language=language)
        compliance_items.append(
            f"- Faille : {v_name}\n"
            f"  * ISO 27001: {m['iso']}\n"
            f"  * GDPR/RGPD: {m['rgpd']}\n"
            f"  * PCI-DSS: {m['pci']}\n"
            f"  * ANSSI: {m['anssi']}\n"
        )
    compliance_context = "\n".join(compliance_items)

    # Valeurs par défaut pour les nouveaux agents
    validator_role = 'Exploit Validation Specialist'
    validator_goal = 'Evaluate threats and design safe, non-destructive validation PoCs to verify vulnerabilities.'
    validator_backstory = (
        "You are a skilled exploit analyst. Your job is to read vulnerability logs and design safe, "
        "non-destructive Proof-of-Concepts (PoCs) to verify if the vulnerability is a true positive. "
        "You provide specific curl commands, header checks, or safe requests."
    )
    
    defender_role = 'Blue Team Active Defender'
    defender_goal = 'Create effective defensive configurations, firewall rules, and Yara detection signatures.'
    defender_backstory = (
        "You are a SecOps engineer and defensive expert. Your job is to create instant mitigation rules. "
        "You write custom Nginx/Apache configuration overrides, ModSecurity WAF rules, iptables firewall "
        "commands, and Yara rules to detect post-exploitation activity."
    )
    
    t_poc_validation = "Validation PoC (Safe & Non-destructive)"
    t_defense_rules = "Active Defense (WAF, Firewall, Yara)"

    # ---------------------------------------------------------
    # TRADUCTIONS ET ADAPTATION DU TEMPLATE
    # ---------------------------------------------------------
    lang_lower = language.lower()
    
    if "anglais" in lang_lower or "english" in lang_lower:
        target_lang_name = "English"
        
        # Agent Properties
        analyst_role = 'Senior Vulnerability Analyst'
        analyst_goal = 'Analyze raw scan results and identify real threats by eliminating false positives.'
        analyst_backstory = (
            "You are an experienced SOC analyst. Your role is to read log lines and JSON data "
            "to extract the essence. You do not let any critical vulnerability slip through, "
            "but you know how to ignore noise (purely informational alerts). You precisely extract "
            "the IP address or host (field \'host\') for each vulnerability."
        )
        
        pentester_role = 'Lead Pentester & Reporter'
        pentester_goal = 'Write a professional and executive security report based on your colleague\'s analysis and internal standards.'
        pentester_backstory = (
            "You are the final report writer. Your ONLY goal is to produce valid Markdown code. "
            "You must NEVER discuss, comment on the analyst\'s work, or say \'Here is the report\'. "
            "You must only write the raw report content, following the requested structure."
        )
        
        # Triage Task
        triage_desc = (
            f"Here is the JSON data generated by Nuclei on target {target_desc} :\n"
            f"```json\n{json_data_str}\n```\n\n"
            "STRICTLY examine this data. Identify each distinct vulnerability PRESENT IN THE JSON. "
            "GOLDEN RULE: DO NOT INVENT ANY VULNERABILITY (e.g. Log4j, random CVE) THAT IS NOT EXPLICITLY WRITTEN IN THE JSON. "
            "If the JSON data only contains basic information (tech-detect, info), indicate that no major vulnerability was found. "
            "IMPERATIVE ACTION: EVEN IF YOU ALREADY KNOW THE VULNERABILITY, you MUST use the web search tool (duckduckgo_search). "
            "Search if a public exploit or \'Proof of Concept\' (PoC) exists for each REAL vulnerability in the JSON.\n\n"
            "TO USE THE TOOL, YOU MUST WRITE EXACTLY:\n"
            "Thought: I need to use the duckduckgo_search tool\n"
            "Action: duckduckgo_search\n"
            "Action Input: [your search query]\n\n"
            "ONCE YOU ARE FINISHED, YOU MUST ABSOLUTELY START YOUR FINAL ANSWER WITH \'Final Answer: \':\n\n"
            "Final Answer:\n"
            "IN YOUR FINAL SUMMARY FOR THE REPORTER, YOU MUST INCLUDE:\n"
            "1. The exact name of the vulnerability and its CVE identifier (if it exists in the JSON).\n"
            "2. The host concerned.\n"
            "3. The severity.\n"
            "4. The URL of a public PoC if you found one via your search, otherwise indicate \'No public PoC identified\'."
        )
        triage_expected = "A technical summary listing for each vulnerability: CVE, host, and the real and complete URL of the PoC if found on the internet."

        # Report Template Fields
        t_title = "Vulnerability Assessment Report"
        t_targets = "Targets audited"
        t_exec_summary = "Executive Summary"
        t_exec_summary_desc = "Write a 3-line executive summary here in English"
        
        # Compliance & ROI Fields
        t_compliance = "Regulatory Compliance"
        t_compliance_placeholder = "Write the mapped requirements for ISO 27001, GDPR, PCI-DSS and ANSSI for this vulnerability exactly from the compliance context provided."
        
        t_financial_title = "Financial Risk & ROI Analysis"
        t_financial_intro = f"Based on our organization's profile (Sector: {sector}, Size: {company_size}, Data Sensitivity: {data_sensitivity}), here is the estimated financial impact of these vulnerabilities if left unmitigated:"
        t_financial_exposure = "Estimated Financial Exposure (Breach Cost)"
        t_financial_remediation = "Estimated Remediation Cost"
        t_financial_net_savings = "Net Savings (Risk Mitigated)"
        t_financial_roi = "Return on Investment (ROI)"
        t_financial_currency = "$"
        t_financial_desc = "Provide a 3-line business explanation in English explaining the financial risk and the ROI of the security fixes."

        t_details = "Technical Details and Remediation"
        t_details_desc = "For EACH vulnerability found by the analyst, create a section with this exact format:"
        t_vuln_name = "Vulnerability Name (CVE if available)"
        t_host = "Vulnerable Host"
        t_severity = "Severity"
        t_description = "Description"
        t_poc = "Proof of Concept (PoC)"
        t_reco = "Recommendation"
        rag_default = "No internal standard found for these vulnerabilities."
        t_reco_desc = "Provide a concrete technical recommendation in English using EXCLUSIVELY this RAG context: {rag_context_val}"
        
        # Placeholders
        t_exec_placeholder = "Write a global executive summary here in 3 lines"
        t_each_vuln_placeholder = "For EACH vulnerability found by the analyst, create a section with this exact format:"
        t_host_placeholder = "IP or URL of the host"
        t_severity_placeholder = "Severity"
        t_description_placeholder = "Detailed explanation of the impact"
        t_poc_placeholder = "Real URL of the PoC found by the analyst, or \'No public PoC identified\'"
    
    elif "espagnol" in lang_lower or "spanish" in lang_lower:
        target_lang_name = "Spanish"
        
        # Agent Properties
        analyst_role = 'Analista de Vulnerabilidades Senior'
        analyst_goal = 'Analizar los resultados brutos del escaneo e identificar las verdaderas amenazas eliminando los falsos positivos.'
        analyst_backstory = (
            "Eres un analista SOC experimentado. Tu rol es leer líneas de logs y datos JSON "
            "para extraer la esencia. No dejas pasar ninguna vulnerabilidad crítica, "
            "pero sabes ignorar el ruido (alertas puramente informativas). Extraes con precisión "
            "la dirección IP o el host (campo \'host\') para cada vulnerabilidad."
        )
        
        pentester_role = 'Pentester Líder y Relator'
        pentester_goal = 'Redactar un informe de seguridad profesional y ejecutivo basado en el análisis de tu colega y los estándares internos.'
        pentester_backstory = (
            "Eres el redactor final. Tu ÚNICO objetivo es producir código Markdown válido. "
            "NUNCA debes discutir, comentar sobre el trabajo del analista, ni decir \'Aquí está el informe\'. "
            "Solo debes escribir el contenido bruto del informe, respetando la estructura solicitada."
        )
        
        # Triage Task
        triage_desc = (
            f"Aquí están los datos JSON generados por Nuclei en el objetivo {target_desc} :\n"
            f"```json\n{json_data_str}\n```\n\n"
            "Examine ESTRICTAMENTE estos datos. Identifique cada vulnerabilidad distinta PRESENTE EN EL JSON. "
            "REGLA DE ORO: NO INVENTE NINGUNA VULNÉRABILIDAD (por ejemplo, Log4j, CVE aleatorio) QUE NO ESTÉ EXPLÍCITAMENTE ESCRITA EN EL JSON. "
            "Si los datos JSON solo contienen información básica (tech-detect, info), indique que no se encontró ninguna vulnerabilidad importante. "
            "ACCIÓN IMPERATIVA: INCLUSO SI YA CONOCE LA VULNÉRABILIDAD, DEBE utilizar la herramienta de búsqueda web (duckduckgo_search). "
            "Busque si existe un exploit público o \'Prueba de concepto\' (PoC) para cada vulnerabilidad REAL en el JSON.\n\n"
            "PARA USAR LA HERRAMIENTA, DEBE ESCRIBIR EXACTAMENTE:\n"
            "Thought: I need to use the duckduckgo_search tool\n"
            "Action: duckduckgo_search\n"
            "Action Input: [su consulta de búsqueda]\n\n"
            "UNA VEZ QUE HAYA TERMINADO, DEBE COMENZAR ABSOLUTAMENTE SU RESPUESTA FINAL CON \'Final Answer: \':\n\n"
            "Final Answer:\n"
            "EN SU RESUMEN FINAL PARA EL RELATOR, DEBE INCLUIR:\n"
            "1. El nombre exacto de la vulnerabilidad y su identificador CVE (si existe en el JSON).\n"
            "2. El host afectado.\n"
            "3. La severidad.\n"
            "4. El URL de un PoC público si encontró uno a través de su búsqueda; de lo contrario, indique \'No se identificó ningún PoC público\'."
        )
        triage_expected = "Un resumen técnico que enumere para cada vulnerabilidad: CVE, host y la URL real y completa del PoC si se encontró en Internet."

        # Report Template Fields
        t_title = "Informe de Evaluación de Vulnerabilidades"
        t_targets = "Objetivos auditados"
        t_exec_summary = "Resumen Ejecutivo"
        t_exec_summary_desc = "Escribe un resumen ejecutivo de 3 líneas aquí en español"
        
        # Compliance & ROI Fields
        t_compliance = "Cumplimiento Regulatorio"
        t_compliance_placeholder = "Escriba los requisitos de cumplimiento asociados (ISO 27001, RGPD, PCI-DSS, ANSSI) para esta vulnerabilidad exactamente del contexto proporcionado."
        
        t_financial_title = "Análisis de Riesgo Financiero y ROI"
        t_financial_intro = f"Según el perfil de nuestra organización (Sector: {sector}, Tamaño: {company_size}, Sensibilidad de datos: {data_sensitivity}), aquí se detalla el impacto financiero estimado de estas vulnerabilidades si no se corrigen:"
        t_financial_exposure = "Exposición Financiera Estimada (Costo de Brèche)"
        t_financial_remediation = "Costo de Remediación Estimado"
        t_financial_net_savings = "Ahorros Netos (Riesgo Mitigado)"
        t_financial_roi = "Retorno de la Inversión (ROI)"
        t_financial_currency = "€"
        t_financial_desc = "Proporcione una breve explicación comercial en español sobre por qué corregir estos problemas ofrece un alto retorno de inversión en seguridad (ROI)."

        t_details = "Detalles Técnicos y Mitigación"
        t_details_desc = "Para CADA vulnerabilidad encontrada por el analista, crea una sección con este formato exacto:"
        t_vuln_name = "Nombre de la vulnerabilidad (CVE si está disponible)"
        t_host = "Host vulnerable"
        t_severity = "Severidad"
        t_description = "Descripción"
        t_poc = "Prueba de concepto (PoC)"
        t_reco = "Recomendación"
        rag_default = "No se encontraron estándares internos para estas vulnerabilidades."
        t_reco_desc = "Proporciona una recomendación técnica concreta en español utilizando EXCLUSIVAMENTE este contexto RAG: {rag_context_val}"
        
        # Placeholders
        t_exec_placeholder = "Ecriba un resumen ejecutivo global aquí en 3 líneas"
        t_each_vuln_placeholder = "Para CADA vulnerabilidad encontrada por el analista, cree una sección con este formato exacto:"
        t_host_placeholder = "IP o URL del host"
        t_severity_placeholder = "Severidad"
        t_description_placeholder = "Explicación detallada del impacto"
        t_poc_placeholder = "URL real del PoC encontrada por el analista, o \'No se identificó ningún PoC público\'"
        
    elif "allemand" in lang_lower or "german" in lang_lower:
        target_lang_name = "German"
        
        # Agent Properties
        analyst_role = 'Senior-Sicherheitsanalyst'
        analyst_goal = 'Analisieren Sie rohe Scan-Ergebnisse und identifizieren Sie echte Bedrohungen, indem Sie Fehlalarme ausschließen.'
        analyst_backstory = (
            "Sie sind ein erfahrener SOC-Analyst. Ihre Aufgabe ist es, Protokollzeilen und JSON-Daten "
            "zu lesen, um das Wesentliche zu extrahieren. Sie übersehen keine kritische Schwachstelle, "
            "wissen aber, wie Sie Rauschen (rein informative Warnungen) ignorieren. Sie extrahieren präzise "
            "die IP-Adresse oder den Host (Feld \'host\') für jede Schwachstelle."
        )
        
        pentester_role = 'Lead Pentester & Berichterstatter'
        pentester_goal = 'Schreiben Sie einen professionellen Sicherheitsbericht basierend auf der Analyse Ihres Kollegen und internen Standards.'
        pentester_backstory = (
            "Sie sind der endgültige Berichterstatter. Ihr EINZIGES Ziel ist es, gültigen Markdown-Code zu erstellen. "
            "Sie dürfen NIEMALS diskutieren, die Arbeit des Analysten kommentieren oder sagen \'Hier ist der Bericht\'. "
            "Sie dürfen nur den rohen Inhalt des Berichts schreiben und dabei die geforderte Struktur einhalten."
        )
        
        # Triage Task
        triage_desc = (
            f"Hier sind die von Nuclei für das Ziel {target_desc} generierten JSON-Daten:\n"
            f"```json\n{json_data_str}\n```\n\n"
            "Untersuchen Sie diese Daten STRENGSTENS. Identifizieren Sie jede einzelne im JSON enthaltene Schwachstelle. "
            "GOLDENE REGEL: ERFINDEN SIE KEINE SCHWACHSTELLEN (z. B. Log4j, zufällige CVEs), DIE NICHT EXPLIZIT IM JSON STEHEN. "
            "Wenn die JSON-Daten nur grundlegende Informationen (tech-detect, info) enthalten, geben Sie an, dass keine schwerwiegende Schwachstelle gefunden wurde. "
            "DRINGENDE AKTION: AUCH WENN SIE DIE SCHWACHSTELLE BEREITS KENNEN, MÜSSEN SIE das Web-Suchwerkzeug (duckduckgo_search) verwenden. "
            "Suchen Sie nach einem öffentlichen Exploit oder \'Proof of Concept\' (PoC) für jede ECHTE Schwachstelle im JSON.\n\n"
            "UM DAS WERKZEUG ZU VERWENDEN, MÜSSEN SIE GENAU SCHREIBEN:\n"
            "Thought: I need to use the duckduckgo_search tool\n"
            "Action: duckduckgo_search\n"
            "Action Input: [Ihre Suchanfrage]\n\n"
            "SOBALD SIE FERTIG SIND, MÜSSEN SIE IHRE ANTWORT UNBEDINGT MIT \'Final Answer: \' BEGINNEN:\n\n"
            "Final Answer:\n"
            "IN IHRER ABSCHLIESSENDEN ZUSAMMENFASSUNG FÜR DEN BERICHTERSTATTER MÜSSEN SIE FOLGENDES ANGEBEN:\n"
            "1. Den genauen Namen der Schwachstelle und ihre CVE-Kennung (falls im JSON vorhanden).\n"
            "2. Den betroffenen Host.\n"
            "3. Den Schweregrad.\n"
            "4. Die URL eines öffentlichen PoC, falls bei der Suche einer gefunden wurde, andernfalls \'Kein öffentlicher PoC identifiziert\'."
        )
        triage_expected = "Eine technische Zusammenfassung, die für jede Schwachstelle Folgendes auflistet: CVE, Host und die tatsächliche und vollständige URL des PoCs, falls im Internet gefunden."

        # Report Template Fields
        t_title = "Schwachstellenbewertungsbericht"
        t_targets = "Geprüfte Ziele"
        t_exec_summary = "Zusammenfassung"
        t_exec_summary_desc = "Schreiben Sie hier eine 3-zeilige Zusammenfassung auf Deutsch"
        
        # Compliance & ROI Fields
        t_compliance = "Regulatorische Konformität"
        t_compliance_placeholder = "Schreiben Sie die zugeordneten Anforderungen für ISO 27001, DSGVO, PCI-DSS und ANSSI für diese Schwachstelle genau aus dem bereitgestellten Compliance-Kontext auf."
        
        t_financial_title = "Finanzrisiko- & ROI-Analyse"
        t_financial_intro = f"Basierend auf dem Profil unserer Organisation (Branche: {sector}, Größe: {company_size}, Datensensibilität: {data_sensitivity}) ist hier die geschätzte finanzielle Auswirkung dieser Schwachstellen, falls sie nicht behoben werden:"
        t_financial_exposure = "Geschätztes finanzielles Risiko (Bruchkosten)"
        t_financial_remediation = "Geschätzte Behebungskosten"
        t_financial_net_savings = "Nettoersparnis (gemindertes Risiko)"
        t_financial_roi = "Return on Investment (ROI)"
        t_financial_currency = "€"
        t_financial_desc = "Geben Sie eine kurze geschäftliche Erklärung auf Deutsch ab, warum sich Behebungen finanziell lohnen (ROI)."

        t_details = "Technische Details und Behebung"
        t_details_desc = "Erstellen Sie für JEDE vom Analysten gefundene Schwachstelle einen Abschnitt in genau diesem Format:"
        t_vuln_name = "Name der Schwachstelle (CVE falls vorhanden)"
        t_host = "Gefährdeter Host"
        t_severity = "Schweregrad"
        t_description = "Beschreibung"
        t_poc = "Proof of Concept (PoC)"
        t_reco = "Empfehlung"
        rag_default = "Keine internen Standards für diese Schwachstellen gefunden."
        t_reco_desc = "Geben Sie eine konkrete technische Empfehlung auf Deutsch unter AUSSCHLIESSLICHER Verwendung dieses RAG-Kontexts: {rag_context_val}"
        
        # Placeholders
        t_exec_placeholder = "Schreiben Sie hier eine 3-zeilige Zusammenfassung auf Deutsch"
        t_each_vuln_placeholder = "Erstellen Sie für JEDE vom Analysten gefundene Schwachstelle einen Abschnitt in genau diesem Format:"
        t_host_placeholder = "IP oder URL des Hosts"
        t_severity_placeholder = "Schweregrad"
        t_description_placeholder = "Detaillierte Beschreibung der Auswirkungen"
        t_poc_placeholder = "Tatsächliche URL des vom Analysten gefundenen PoCs oder \'Kein öffentlicher PoC identifiziert\'"
        
    else:
        target_lang_name = "French"
        
        # Agent Properties
        validator_role = 'Spécialiste en Validation d\'Exploits'
        validator_goal = 'Évaluer les menaces et concevoir des PoC de validation sûrs et non destructifs pour vérifier les failles.'
        validator_backstory = (
            "Tu es un analyste expert en exploits. Ton rôle est de lire les alertes de vulnérabilité "
            "et de concevoir des Preuves de Concept (PoC) de validation sûres et non invasives pour vérifier "
            "que la faille est réelle. Tu fournis des commandes curl ou des requêtes de test inoffensives."
        )
        
        defender_role = 'Défenseur Actif de la Blue Team'
        defender_goal = 'Créer des configurations défensives efficaces, des règles de pare-feu et des signatures de détection Yara.'
        defender_backstory = (
            "Tu es un ingénieur SecOps et expert défensif. Ton rôle est de concevoir des règles de mitigation instantanées. "
            "Tu rédiges des règles de WAF ModSecurity, des blocs Nginx, des commandes iptables, et des règles Yara."
        )
        
        t_poc_validation = "PoC de Validation (Sûr & Non destructif)"
        t_defense_rules = "Défense Active (WAF, Firewall, Yara)"

        analyst_role = 'Vulnerability Analyst Senior'
        analyst_goal = 'Analyser les résultats bruts de scan et identifier les véritables menaces en éliminant les faux positifs.'
        analyst_backstory = (
            "Tu es un analyste SOC expérimenté. Ton rôle est de lire des lignes de logs "
            "et de JSON pour en extraire l\'essence. Tu ne laisses passer aucune faille critique, "
            "mais tu sais ignorer le bruit (les alertes purement informatives). Tu extrais précisément "
            "l\'adresse IP ou l\'hôte (champ \'host\') pour chaque vulnérabilité."
        )
        
        pentester_role = 'Lead Pentester & Rapporteur'
        pentester_goal = 'Rédiger un rapport de sécurité professionnel et exécutif basé sur l\'analyse de ton colègue et les normes internes.'
        pentester_backstory = (
            "Tu es le rédacteur final. Ton SEUL but est de produire du code Markdown valide. "
            "Tu ne dois JAMAIS discuter, ni donner ton avis sur le travail de l\'analyste, ni dire \'Voici le rapport\'. "
            "Tu dois uniquement écrire le contenu du rapport brut, en respectant la structure demandée."
        )
        
        # Triage Task
        triage_desc = (
            f"Voici les données JSON générées par Nuclei sur la cible {target_desc} :\n"
            f"```json\n{json_data_str}\n```\n\n"
            "Examine STRICTEMENT ces données. Identifie chaque vulnérabilité distincte PRÉSENT DANS LE JSON. "
            "RÈGLE D\'OR : N\'INVENTE AUCUNE VULNÉRABILITÉ (ex: Log4j, CVE aléatoire) QUI NE SOIT PAS EXPLICITEMENT ÉCRITE DANS LE JSON. "
            "Si les données JSON ne contiennent que des informations de base (tech-detect, info), indique qu\'aucune vulnérabilité majeure n'a été trouvée. "
            "ACTION IMPÉRATIVE : MÊME SI TU CONNAIS DÉJÀ LA VULNÉRABILITÉ, tu DOIS utiliser l'outil de recherche Web (duckduckgo_search). "
            "Cherche si un exploit ou \'Proof of Concept\' (PoC) public existe pour chaque faille REELLE du JSON.\n\n"
            "POUR UTILISER L'OUTIL, TU DOIS ÉCRIRE EXACTEMENT :\n"
            "Thought: I need to use the duckduckgo_search tool\n"
            "Action: duckduckgo_search\n"
            "Action Input: [ta recherche]\n\n"
            "UNE FOIS QUE TU AS TERMINÉ, TU DOIS IMPÉRATIVEMENT COMMENCER TA RÉPONSE PAR \'Final Answer: \' :\n\n"
            "Final Answer:\n"
            "DANS TON RÉSUMÉ FINAL POUR LE RAPPORTEUR, TU DOIS INCLURE :\n"
            "1. Le nom exact de la faille et son identifiant CVE (s\'il existe dans le JSON).\n"
            "2. L\'hôte concerné.\n"
            "3. La sévérité.\n"
            "4. L\'URL d\'un PoC public si tu en as trouvé un via ta recherche, sinon indique \'Aucun PoC identifié\'."
        )
        triage_expected = "Un résumé technique listant pour chaque faille: la CVE, l'hôte, et l'URL réelle et complète du PoC s'il a été trouvé sur internet."
        
        # Report Template Fields
        t_title = "Rapport d'Évaluation de Vulnérabilités"
        t_targets = "Cibles auditées"
        t_exec_summary = "Résumé Exécutif"
        t_exec_summary_desc = "Rédige ici un résumé exécutif global en 3 lignes en français"
        
        # Compliance & ROI Fields
        t_compliance = "Conformité Réglementaire"
        t_compliance_placeholder = "Écris les clauses de conformité associées (ISO 27001, RGPD, PCI-DSS, ANSSI) pour cette vulnérabilité en copiant exactement le contexte de conformité fourni."
        
        t_financial_title = "Analyse des Risques Financiers et ROI"
        t_financial_intro = f"Sur la base du profil de l'organisation (Secteur : {sector}, Taille : {company_size}, Sensibilité des données : {data_sensitivity}), voici l'estimation de l'impact financier de ces vulnérabilités si elles ne sont pas corrigées :"
        t_financial_exposure = "Exposition Financière Estimée (Coût de la Brèche)"
        t_financial_remediation = "Coût de Remédiation Estimé"
        t_financial_net_savings = "Économies Nettes (Risque Évité)"
        t_financial_roi = "Retour sur Investissement (ROI)"
        t_financial_currency = "€"
        t_financial_desc = "Rédige une explication commerciale en français expliquant le risque financier et le ROI de la remédiation."

        t_details = "Détails Techniques et Remédiation"
        t_details_desc = "Pour CHAQUE vulnérabilité trouvée par l'analyste, crée une section avec ce format exact :"
        t_vuln_name = "Nom de la vulnérabilité (CVE si disponible)"
        t_host = "Hôte vulnérable"
        t_severity = "Sévérité"
        t_description = "Description"
        t_poc = "Preuve de concept (PoC)"
        t_reco = "Recommandation"
        rag_default = "Aucun standard interne trouvé pour ces failles."
        t_reco_desc = "Propose une recommandation technique concrète en français en t'aidant EXCLUSIVEMENT de ce contexte RAG : {rag_context_val}"

        # Placeholders
        t_exec_placeholder = "Rédige ici un résumé exécutif global en 3 lignes en français"
        t_each_vuln_placeholder = "Pour CHAQUE vulnérabilité trouvée par l'analyste, crée une section avec ce format exact :"
        t_host_placeholder = "IP ou URL de l'hôte"
        t_severity_placeholder = "Sévérité"
        t_description_placeholder = "Explication détaillée de l'impact"
        t_poc_placeholder = "URL réelle du PoC trouvée par l'analyste, ou \'Aucun PoC public identifié\'"

    rag_safe_context = rag_context if rag_context else rag_default
    t_reco_desc_formatted = t_reco_desc.format(rag_context_val=rag_safe_context)

    # Enlever None ou dictionnaires vides et assurer le fallback pour les tables
    active_breach = custom_breach if custom_breach else roi_calculator.BASE_BREACH_COSTS
    active_remed = custom_remed if custom_remed else roi_calculator.BASE_REMEDIATION_COSTS

    # Déterminer la langue pour adapter le texte explicatif de la section financière
    if "anglais" in lang_lower or "english" in lang_lower:
        justification_details = f"""
### Methodology & Financial Cost Justifications (DORA, GDPR, NIS 2)

The financial calculations are tailored based on your organization's specific profile:
- **Sector ({sector})**: Multiplier `{roi_data['applied_multipliers']['sector']}x` applied. (Reflects regulatory overhead like DORA or HIPAA and direct cyberattack attractiveness).
- **Company Size ({company_size})**: Multiplier `{roi_data['applied_multipliers']['size']}x` applied. (Reflects scale of operations, number of targets/users, and complexity of security governance).
- **Data Sensitivity ({data_sensitivity})**: Multiplier `{roi_data['applied_multipliers']['sensitivity']}x` applied. (Reflects the liability, class action risk, and GDPR notification costs associated with data breaches).

#### 🛡️ Base Financial Model & Severity Justification:

| Severity | Base Exposure Cost | Base Remediation Cost | Business & Regulatory Justification |
| :--- | :--- | :--- | :--- |
| 🔴 **Critical** | {active_breach.get('critical', 150000.0):,.2f} {t_financial_currency} | {active_remed.get('critical', 4000.0):,.2f} {t_financial_currency} | Ransomware threat, massive GDPR breach, DORA non-compliance. Urgent hot patching & expert mobilization. |
| 🟠 **High** | {active_breach.get('high', 60000.0):,.2f} {t_financial_currency} | {active_remed.get('high', 2000.0):,.2f} {t_financial_currency} | Production server access. Triggers mandatory regulatory breach notification under GDPR/NIS 2. Prioritized CI/CD deployment. |
| 🟡 **Medium** | {active_breach.get('medium', 15000.0):,.2f} {t_financial_currency} | {active_remed.get('medium', 800.0):,.2f} {t_financial_currency} | Information disclosure or elevation of privilege. standard patch & configuration management. |
| 🟢 **Low** | {active_breach.get('low', 3000.0):,.2f} {t_financial_currency} | {active_remed.get('low', 200.0):,.2f} {t_financial_currency} | Informational leakage, minor configuration drift. Simple configuration adjustment. |

#### 📐 Calculation Logic:
1. **Financial Exposure (Gross Risk)**: Sum of base breach costs × Combined Multiplier (`{roi_data['applied_multipliers']['overall']:.3f}x`).
2. **Remediation Cost**: Base engineering cost scaled by organization size (+30% for Mid-market, +80% for Enterprise) to account for change management and approval cycles.
3. **Residual Risk (5%)**: Cybersecurity does not have zero risk; 5% risk is preserved for human errors, future configuration drifts, and zero-day vulnerabilities.
4. **Net Savings**: `Financial Exposure - Remediation Cost - Residual Risk` (Total financial loss avoided).
5. **ROI Cyber**: `(Net Savings / Remediation Cost) * 100` (Percentage return on security spend).
"""
    else:
        justification_details = f"""
### Méthodologie et Justification des Coûts Financiers (RGPD, DORA, NIS 2)

Les calculs financiers sont personnalisés selon le profil spécifique de votre organisation :
- **Secteur d'Activité ({sector})** : Coefficient `{roi_data['applied_multipliers']['sector']}x` appliqué. ({roi_data['multiplier_justifications']['sector'].get(sector, '')})
- **Taille de l'Entreprise ({company_size})** : Coefficient `{roi_data['applied_multipliers']['size']}x` appliqué. ({roi_data['multiplier_justifications']['company_size'].get(company_size, '')})
- **Sensibilité des Données ({data_sensitivity})** : Coefficient `{roi_data['applied_multipliers']['sensitivity']}x` appliqué. ({roi_data['multiplier_justifications']['data_sensitivity'].get(data_sensitivity, '')})

#### 🛡️ Modèle de Coût de Base et Justification par Sévérité :

| Sévérité | Exposition de Base | Remédiation de Base | Justification Métier & Réglementaire |
| :--- | :--- | :--- | :--- |
| 🔴 **Critique** | {active_breach.get('critical', 150000.0):,.2f} {t_financial_currency} | {active_remed.get('critical', 4000.0):,.2f} {t_financial_currency} | {roi_data['exposure_justifications']['critical']} |
| 🟠 **Élevée** | {active_breach.get('high', 60000.0):,.2f} {t_financial_currency} | {active_remed.get('high', 2000.0):,.2f} {t_financial_currency} | {roi_data['exposure_justifications']['high']} |
| 🟡 **Moyenne** | {active_breach.get('medium', 15000.0):,.2f} {t_financial_currency} | {active_remed.get('medium', 800.0):,.2f} {t_financial_currency} | {roi_data['exposure_justifications']['medium']} |
| 🟢 **Faible** | {active_breach.get('low', 3000.0):,.2f} {t_financial_currency} | {active_remed.get('low', 200.0):,.2f} {t_financial_currency} | {roi_data['exposure_justifications']['low']} |

#### 📐 Formules Mathématiques du Modèle :
1. **Exposition Financière (Risque Brut)** : Somme des coûts de base de brèche × Multiplicateur Global (`{roi_data['applied_multipliers']['overall']:.3f}x`).
2. **Coût de Remédiation** : Somme des coûts d'ingénierie de base, ajustée selon la taille (+30% pour les ETI, +80% pour les Grandes Entreprises) pour intégrer la complexité opérationnelle cyber.
3. **Risque Résiduel (5%)** : {roi_data['metric_explanations']['residual_risk']}
4. **Économies Nettes** : `Exposition Financière - Coût de Remédiation - Risque Résiduel` (Bénéfice net direct des corrections).
5. **ROI Cyber** : `(Économies Nettes / Coût de Remédiation) * 100` (Efficacité financière des dépenses).
"""

    # Construire la section financière pré-calculée en Python pour éviter les erreurs de calcul du modèle
    financial_section_str = (
        f"## {t_financial_title}\n"
        f"{t_financial_intro}\n\n"
        f"- **{t_financial_exposure}** : {roi_data['total_exposure']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_remediation}** : {roi_data['total_remediation']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_net_savings}** : {roi_data['net_savings']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_roi}** : {roi_data['roi_pct']:.2f} %\n\n"
        f"({t_financial_desc})\n\n"
        f"{justification_details}"
    )

    # ---------------------------------------------------------
    # DÉFINITION DES AGENTS (L'Équipe)
    # ---------------------------------------------------------
    analyst_agent = Agent(
        role=analyst_role,
        goal=analyst_goal,
        backstory=analyst_backstory,
        verbose=True,
        allow_delegation=False,
        llm=active_llm,
        tools=[search_tool]
    )

    pentester_agent = Agent(
        role=pentester_role,
        goal=pentester_goal,
        backstory=pentester_backstory,
        verbose=True,
        allow_delegation=False,
        llm=active_llm
    )

    exploit_validator_agent = Agent(
        role=validator_role,
        goal=validator_goal,
        backstory=validator_backstory,
        verbose=True,
        allow_delegation=False,
        llm=active_llm
    )

    defender_agent = Agent(
        role=defender_role,
        goal=defender_goal,
        backstory=defender_backstory,
        verbose=True,
        allow_delegation=False,
        llm=active_llm
    )

    # ---------------------------------------------------------
    # DÉFINITION DES TÂCHES (Le Workflow)
    # ---------------------------------------------------------
    triage_task = Task(
        description=triage_desc,
        expected_output=triage_expected,
        agent=analyst_agent
    )

    validation_task = Task(
        description=(
            "Analyse les vulnérabilités trouvées par l'analyste. Pour chaque vulnérabilité critique ou haute, "
            "conçois un protocole de validation (Proof of Concept) sûr et non destructif (ex: requête HTTP spécifique, "
            "vérification d'en-tête de réponse, commande système de diagnostic). Décris comment reproduire de manière sécurisée."
        ),
        expected_output="Guide technique décrivant les étapes et commandes pour valider de manière sûre chaque vulnérabilité.",
        agent=exploit_validator_agent
    )

    defender_task = Task(
        description=(
            "Sur la base des vulnérabilités identifiées et validées, propose des correctifs et des règles de défense active. "
            "Génère spécifiquement : 1. Une règle de pare-feu applicatif WAF (ex: ModSecurity), 2. Des règles de pare-feu réseau (iptables/nftables), "
            "3. Une signature de détection Yara pour identifier les tentatives d'exploitation de ces failles."
        ),
        expected_output="Règles de défense active (WAF ModSecurity, Firewall iptables, Signatures Yara) adaptées aux failles.",
        agent=defender_agent
    )

    report_task = Task(
        description=(
            f"Prends l'analyse technique de l'analyste, les PoCs de validation et les règles de défense active, et rédige le rapport final de sécurité.\n\n"
            f"ATTENTION : Tu dois générer un rapport complet en Markdown basé UNIQUEMENT sur les VRAIES données transmises par l'analyste. "
            f"N'INVENTE AUCUNE VULNÉRABILITÉ. Ne copie pas de texte à trous. Tu dois écrire les vraies valeurs.\n\n"
            f"RÈGLE DE LANGUE IMPORTANTE : Tu DOIS rédiger l'INTEGRALITÉ du rapport (les titres, la description, les recommandations, le résumé exécutif) en {target_lang_name}.\n\n"
            f"CONTEXTE DE CONFORMITÉ RÉGLEMENTAIRE À REPORTER :\n"
            f"{compliance_context}\n\n"
            f"POUR SATISFAIRE LE SYSTÈME, TU DOIS IMPÉRATIVEMENT COMMENCER TA RÉPONSE EXACTEMENT PAR 'Final Answer: ' SUIVI DU MARKDOWN :\n\n"
            f"Final Answer:\n"
            f"# {t_title}\n"
            f"{t_targets} : {target_desc}\n\n"
            f"## {t_exec_summary}\n"
            f"({t_exec_placeholder})\n\n"
            f"{financial_section_str}\n\n"
            f"## {t_details}\n"
            f"({t_each_vuln_placeholder})\n"
            f"### {t_vuln_name}\n"
            f"- **{t_host}** : ({t_host_placeholder})\n"
            f"- **{t_severity}** : ({t_severity_placeholder})\n"
            f"- **{t_description}** : ({t_description_placeholder})\n"
            f"- **{t_poc}** : ({t_poc_placeholder})\n"
            f"- **{t_poc_validation}** : (Proposer un PoC de validation sûr et inoffensif sur la base du travail de validation_task)\n"
            f"- **{t_defense_rules}** : (Proposer des règles WAF ModSecurity, iptables, et signatures Yara sur la base de defender_task)\n"
            f"- **{t_compliance}** : ({t_compliance_placeholder})\n"
            f"- **{t_reco}** : ({t_reco_desc_formatted})\n"
        ),
        expected_output=f"Le rapport de sécurité final en Markdown rédigé en {target_lang_name}, avec les vraies données insérées et sans aucun texte entre crochets.",
        agent=pentester_agent
    )

    # ---------------------------------------------------------
    # TRADUCTION DE FIN PAR AGENT DÉDIÉ (SI NON FRANÇAIS)
    # ---------------------------------------------------------
    agents_list = [analyst_agent, exploit_validator_agent, defender_agent, pentester_agent]
    tasks_list = [triage_task, validation_task, defender_task, report_task]
    
    if "français" not in lang_lower and "french" not in lang_lower:
        translator_agent = Agent(
            role='Expert Translator',
            goal=f'Translate the security report accurately into {target_lang_name} while preserving all Markdown formatting, HTML styles, and technical terms.',
            backstory=(
                "You are a professional cybersecurity translator. Your job is to translate technical "
                "reports from French to the target language without altering code blocks, JSON snippets, "
                "URLs, file links, tables, or the Markdown structure."
            ),
            verbose=True,
            allow_delegation=False,
            llm=active_llm
        )
        
        translation_task = Task(
            description=(
                f"Translate the final security report generated by your colleague (the reporter) into {target_lang_name}.\n"
                "Keep all tables, bullet points, code blocks, CVE names, host addresses, compliance clauses, "
                "and formatting exactly intact. Only translate the human explanations and descriptions.\n\n"
                "YOUR RESPONSE MUST START EXACTLY WITH 'Final Answer: ' followed by the raw translated Markdown."
            ),
            expected_output=f"The complete technical security report translated into {target_lang_name}.",
            agent=translator_agent
        )
        
        agents_list.append(translator_agent)
        tasks_list.append(translation_task)

    # ---------------------------------------------------------
    # ORCHESTRATION (LA CREW)
    # ---------------------------------------------------------
    cyber_crew = Crew(
        agents=agents_list,
        tasks=tasks_list,
        process=Process.sequential,
        verbose=True
    )

    # Lancement du processus
    result = cyber_crew.kickoff()
    
    # CrewAI 0.11.2 retourne directement une string
    if isinstance(result, str):
        return result
    return getattr(result, 'raw', str(result))

def run_host_audit_crew(host, structured_output, language="Français"):
    """
    Utilise CrewAI pour analyser les résultats de l'audit local (SUID, Sudo, Kernel, etc.)
    et rédiger un rapport d'audit interne avec les risques d'élévation de privilèges.
    """
    import report_config
    rep_cfg = report_config.load_report_config()
    active_llm = get_configured_llm(rep_cfg)
    
    analyst = Agent(
        role="Spécialiste de l'Élévation de Privilèges",
        goal="Analyser les configurations système locales pour identifier les failles d'élévation de privilèges (LPE).",
        backstory="Tu es un chercheur en sécurité expert des systèmes d'exploitation. Tu analyses les SUID, règles Sudo, tâches Cron et versions de noyaux pour trouver des vecteurs de compromission locale.",
        verbose=True,
        allow_delegation=False,
        llm=active_llm
    )
    
    writer = Agent(
        role="Rapporteur d'Audit Interne",
        goal="Rédiger un rapport d'audit système clair et exploitable contenant les vulnérabilités trouvées et les recommandations de durcissement.",
        backstory="Tu es un auditeur de sécurité système. Ton rôle est de documenter précisément les failles trouvées par ton collègue et de fournir les commandes d'administration pour les corriger.",
        verbose=True,
        allow_delegation=False,
        llm=active_llm
    )
    
    task_analysis = Task(
        description=f"Voici les données d'audit système brutes obtenues sur {host} :\n\n{structured_output}\n\nExamine attentivement les SUID/SGID, fichiers sensibles, configurations sudo, noyau, capabilities Linux, ports en écoute locale, accès au socket Docker, variables d'environnement exposant des secrets et historique des commandes. Identifie tous les risques et vecteurs réels d'élévation de privilèges (LPE) ou de fuite d'informations. Explique précisément chaque vecteur potentiel.",
        expected_output="Une liste structurée des vulnérabilités locales et des vecteurs d'élévation de privilèges identifiés avec le composant vulnérable.",
        agent=analyst
    )
    
    task_report = Task(
        description=f"Rédige un rapport complet en Markdown rédigé intégralement en {language}. Structure-le avec : # Rapport d'Audit Système local - {host}, ## Résumé Exécutif, ## Vecteurs d'Élévation de Privilèges Identifiés (SUID/Sudo/Kernel/Capabilities/Docker), ## Analyse de la Surface d'Exposition (Fichiers, Dossiers, Ports, Secrets), ## Recommandations de Durcissement (CIS/ANSSI/Docker/Secrets).",
        expected_output="Le rapport d'audit système complet en Markdown.",
        agent=writer
    )
    
    crew = Crew(
        agents=[analyst, writer],
        tasks=[task_analysis, task_report],
        process=Process.sequential,
        verbose=True
    )
    
    result = crew.kickoff()
    if isinstance(result, str):
        return result
    return getattr(result, 'raw', str(result))



