import json
import ast

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
    base_url="http://localhost:11434"
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
    
    # Calculer le ROI et risque financier
    roi_data = roi_calculator.calculate_financial_risk(
        nuclei_results, 
        sector, 
        company_size, 
        data_sensitivity
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

    # Construire la section financière pré-calculée en Python pour éviter les erreurs de calcul du modèle
    financial_section_str = (
        f"## {t_financial_title}\n"
        f"{t_financial_intro}\n\n"
        f"- **{t_financial_exposure}** : {roi_data['total_exposure']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_remediation}** : {roi_data['total_remediation']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_net_savings}** : {roi_data['net_savings']:,.2f} {t_financial_currency}\n"
        f"- **{t_financial_roi}** : {roi_data['roi_pct']:.2f} %\n\n"
        f"({t_financial_desc})"
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
        llm=local_llm,
        tools=[search_tool]
    )

    pentester_agent = Agent(
        role=pentester_role,
        goal=pentester_goal,
        backstory=pentester_backstory,
        verbose=True,
        allow_delegation=False,
        llm=local_llm
    )

    # ---------------------------------------------------------
    # DÉFINITION DES TÂCHES (Le Workflow)
    # ---------------------------------------------------------
    triage_task = Task(
        description=triage_desc,
        expected_output=triage_expected,
        agent=analyst_agent
    )

    report_task = Task(
        description=(
            f"Prends l'analyse technique de l'analyste et rédige le rapport final de sécurité.\n\n"
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
            f"- **{t_compliance}** : ({t_compliance_placeholder})\n"
            f"- **{t_reco}** : ({t_reco_desc_formatted})\n"
        ),
        expected_output=f"Le rapport de sécurité final en Markdown rédigé en {target_lang_name}, avec les vraies données insérées et sans aucun texte entre crochets.",
        agent=pentester_agent
    )

    # ---------------------------------------------------------
    # ORCHESTRATION (LA CREW)
    # ---------------------------------------------------------
    cyber_crew = Crew(
        agents=[analyst_agent, pentester_agent],
        tasks=[triage_task, report_task],
        process=Process.sequential,
        verbose=True
    )

    # Lancement du processus
    result = cyber_crew.kickoff()
    
    # CrewAI 0.11.2 retourne directement une string
    if isinstance(result, str):
        return result
    return getattr(result, 'raw', str(result))

