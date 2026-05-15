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

def run_cyber_crew(target_desc, nuclei_results, rag_context):
    """
    Orchestre une équipe d'agents CrewAI pour analyser et rédiger le rapport.
    Cette fonction remplace l'ancien appel direct et simpliste à Ollama.
    """
    if not nuclei_results:
        return f"# Rapport d'Évaluation de Vulnérabilités\n\nCibles : {target_desc}\n\n## Résumé Exécutif\n\nAucune vulnérabilité n'a été détectée par le scanner sur ces cibles lors de ce test de surface."

    json_data_str = json.dumps(nuclei_results, indent=2)
    rag_safe_context = rag_context if rag_context else "Aucun standard interne trouvé pour ces failles."

    # ---------------------------------------------------------
    # DÉFINITION DES AGENTS (L'Équipe)
    # ---------------------------------------------------------
    analyst_agent = Agent(
        role='Vulnerability Analyst Senior',
        goal='Analyser les résultats bruts de scan et identifier les véritables menaces en éliminant les faux positifs.',
        backstory=(
            "Tu es un analyste SOC expérimenté. Ton rôle est de lire des lignes de logs "
            "et de JSON pour en extraire l'essence. Tu ne laisses passer aucune faille critique, "
            "mais tu sais ignorer le bruit (les alertes purement informatives). Tu extrais précisément "
            "l'adresse IP ou l'hôte (champ 'host') pour chaque vulnérabilité."
        ),
        verbose=True,
        allow_delegation=False,
        llm=local_llm,
        tools=[search_tool]
    )

    pentester_agent = Agent(
        role='Lead Pentester & Rapporteur',
        goal='Rédiger un rapport de sécurité professionnel et exécutif basé sur l\'analyse de ton collègue et les normes internes.',
        backstory=(
            "Tu es le rédacteur final. Ton SEUL but est de produire du code Markdown valide. "
            "Tu ne dois JAMAIS discuter, ni donner ton avis sur le travail de l'analyste, ni dire 'Voici le rapport'. "
            "Tu dois uniquement écrire le contenu du rapport brut, en respectant la structure demandée."
        ),
        verbose=True,
        allow_delegation=False,
        llm=local_llm
    )

    # ---------------------------------------------------------
    # DÉFINITION DES TÂCHES (Le Workflow)
    # ---------------------------------------------------------
    triage_task = Task(
        description=(
            f"Voici les données JSON générées par Nuclei sur la cible {target_desc} :\n"
            f"```json\n{json_data_str}\n```\n\n"
            "Examine STRICTEMENT ces données. Identifie chaque vulnérabilité distincte PRÉSENTE DANS LE JSON. "
            "RÈGLE D'OR : N'INVENTE AUCUNE VULNÉRABILITÉ (ex: Log4j, CVE aléatoire) QUI NE SOIT PAS EXPLICITEMENT ÉCRITE DANS LE JSON. "
            "Si les données JSON ne contiennent que des informations de base (tech-detect, info), indique qu'aucune vulnérabilité majeure n'a été trouvée. "
            "ACTION IMPÉRATIVE : MÊME SI TU CONNAIS DÉJÀ LA VULNÉRABILITÉ, tu DOIS utiliser l'outil de recherche Web (duckduckgo_search). "
            "Cherche si un exploit ou 'Proof of Concept' (PoC) public existe pour chaque faille REELLE du JSON.\n\n"
            "POUR UTILISER L'OUTIL, TU DOIS ÉCRIRE EXACTEMENT :\n"
            "Thought: I need to use the duckduckgo_search tool\n"
            "Action: duckduckgo_search\n"
            "Action Input: [ta recherche]\n\n"
            "UNE FOIS QUE TU AS TERMINÉ, TU DOIS IMPÉRATIVEMENT COMMENCER TA RÉPONSE FINALE PAR 'Final Answer: ' :\n\n"
            "Final Answer:\n"
            "DANS TON RÉSUMÉ FINAL POUR LE RAPPORTEUR, TU DOIS INCLURE :\n"
            "1. Le nom exact de la faille et son identifiant CVE (s'il existe dans le JSON).\n"
            "2. L'hôte concerné.\n"
            "3. La sévérité.\n"
            "4. L'URL d'un PoC public si tu en as trouvé un via ta recherche, sinon indique 'Aucun PoC identifié'."
        ),
        expected_output="Un résumé technique listant pour chaque faille: la CVE, l'hôte, et l'URL réelle et complète du PoC s'il a été trouvé sur internet.",
        agent=analyst_agent
    )

    report_task = Task(
        description=(
            f"Prends l'analyse technique de l'analyste et rédige le rapport final de sécurité.\n\n"
            f"ATTENTION : Tu dois générer un rapport complet en Markdown basé UNIQUEMENT sur les VRAIES données transmises par l'analyste. "
            f"N'INVENTE AUCUNE VULNÉRABILITÉ. Ne copie pas de texte à trous. Tu dois écrire les vraies valeurs.\n\n"
            f"POUR SATISFAIRE LE SYSTÈME, TU DOIS IMPÉRATIVEMENT COMMENCER TA RÉPONSE EXACTEMENT PAR 'Final Answer: ' SUIVI DU MARKDOWN :\n\n"
            f"Final Answer:\n"
            f"# Rapport d'Évaluation de Vulnérabilités\n"
            f"Cibles audités : {target_desc}\n\n"
            f"## Résumé Exécutif\n"
            f"(Rédige ici un résumé exécutif global en 3 lignes)\n\n"
            f"## Détails Techniques et Remédiation\n"
            f"(Pour CHAQUE vulnérabilité trouvée par l'analyste, crée une section avec ce format exact) :\n"
            f"### Nom de la vulnérabilité (CVE si disponible)\n"
            f"- **Hôte vulnérable** : (IP ou URL de l'hôte)\n"
            f"- **Sévérité** : (Sévérité)\n"
            f"- **Description** : (Explication détaillée de l'impact)\n"
            f"- **Preuve de concept (PoC)** : (URL réelle du PoC trouvée par l'analyste, ou 'Aucun PoC public identifié')\n"
            f"- **Recommandation** : (Propose une recommandation technique concrète en t'aidant EXCLUSIVEMENT de ce contexte RAG : {rag_safe_context})\n"
        ),
        expected_output="Le rapport de sécurité final en Markdown, avec les vraies données insérées et sans aucun texte entre crochets.",
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
