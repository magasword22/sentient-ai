from langchain_community.llms import Ollama
try:
    from ddgs import DDGS
except ImportError:
    pass

def get_llm():
    return Ollama(
        model="llama3.1:8b",
        base_url="http://localhost:11434"
    )

def stream_chat_response(report_md, chat_history, query, use_web=False):
    """
    Génère une réponse en streaming (générateur) en utilisant Ollama.
    """
    llm = get_llm()
    
    web_context = ""
    if use_web:
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=3))
            
            if results:
                res_str = "\n".join([f"- {r['title']}: {r['body']}" for r in results])
                web_context = f"\n--- RÉSULTATS DE RECHERCHE WEB EN TEMPS RÉEL ---\n{res_str}\n--------------------------------------------------\n\n"
            else:
                web_context = f"\n[Avertissement: Aucun résultat Web pertinent trouvé]\n\n"
        except Exception as e:
            web_context = f"\n[Avertissement: Recherche Web échouée: {e}]\n\n"
            
    system_prompt = f"""Tu es Sentient AI, un assistant de cybersécurité virtuel avancé.
Ton rôle est d'analyser le rapport d'audit suivant et de répondre aux questions de l'utilisateur.
Sois précis, professionnel, et fournis des recommandations d'experts.
Si la question n'a aucun lien avec la cybersécurité ou le rapport, refuse poliment d'y répondre.

{web_context}--- DÉBUT DU RAPPORT D'AUDIT ---
{report_md}
--- FIN DU RAPPORT D'AUDIT ---

Historique récent de la conversation :
"""

    prompt = system_prompt
    for msg in chat_history[-5:]: # Ne garde que le contexte récent
        role = "Utilisateur" if msg['role'] == "user" else "Sentient AI"
        prompt += f"{role}: {msg['content']}\n"
        
    prompt += f"Utilisateur: {query}\nSentient AI:"
    
    # Retourne un itérateur qui yield les chunks de réponse
    return llm.stream(prompt)
