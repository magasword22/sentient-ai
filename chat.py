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
            # Demander au LLM d'extraire les mots-clés pour optimiser la recherche
            keyword_prompt = f"Extract the most important technical keywords for a Google search (vulnerability name, CVE, etc) from: '{query}'. Return ONLY a space-separated list of 2-3 keywords without any punctuation or commas. If it's a CVE, include the word 'Linux' to help the search engine."
            search_query = llm.invoke(keyword_prompt).strip()
            print(f"[DEBUG] Extracted search query: '{search_query}'")
            
            with DDGS() as ddgs:
                # On cherche avec les mots-clés extraits, pas avec la phrase complète
                results = list(ddgs.text(search_query, max_results=3))
                print(f"[DEBUG] Web search returned {len(results)} results")
            
            if results:
                res_str = "\n".join([f"- {r['title']}: {r['body']}" for r in results])
                web_context = f"\n--- RÉSULTATS DE RECHERCHE WEB EN TEMPS RÉEL (Recherche: {search_query}) ---\n{res_str}\n--------------------------------------------------\n\n"
            else:
                web_context = f"\n[Avertissement: Aucun résultat Web pertinent trouvé pour '{search_query}']\n\n"
        except Exception as e:
            web_context = f"\n[Avertissement: Recherche Web échouée: {e}]\n\n"
            
    system_prompt = f"""Tu es Sentient AI, un assistant de cybersécurité virtuel avancé.
Ton rôle principal est d'analyser le rapport d'audit suivant et de répondre aux questions.
Cependant, tu peux AUSSI utiliser tes connaissances générales et les résultats de la recherche Web pour répondre à des questions de cybersécurité qui ne sont PAS dans le rapport (ex: expliquer une CVE).
Si une recherche Web est fournie, utilise-la pour formuler ta réponse avec précision.
Si la question n'a aucun lien avec la cybersécurité (ex: recette de cuisine, météo), refuse poliment d'y répondre.
Ne dis JAMAIS qu'une faille n'existe pas simplement parce qu'elle n'est pas dans le rapport.

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
