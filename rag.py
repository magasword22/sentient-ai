import os
import chromadb
import hashlib
from io import BytesIO
from pypdf import PdfReader

DB_DIR = "./rag_db"

def get_chroma_client():
    """Initialise le client ChromaDB persistant."""
    return chromadb.PersistentClient(path=DB_DIR)

def get_collection():
    """Récupère ou crée la collection principale."""
    client = get_chroma_client()
    return client.get_or_create_collection(name="knowledge_base")

def extract_text_from_pdf(file_bytes):
    """Extrait le texte brut d'un fichier PDF en mémoire."""
    reader = PdfReader(BytesIO(file_bytes))
    text = ""
    for page in reader.pages:
        extracted = page.extract_text()
        if extracted:
            text += extracted + "\n\n"
    return text

def add_document(content_bytes, filename):
    """Découpe un document en morceaux et l'ajoute à la base vectorielle."""
    collection = get_collection()
    
    # Extraction selon le type
    if filename.lower().endswith('.pdf'):
        text = extract_text_from_pdf(content_bytes)
    else:
        text = content_bytes.decode('utf-8', errors='ignore')
        
    # Découpage naïf par doubles sauts de ligne (paragraphes)
    chunks = [c.strip() for c in text.split('\n\n') if len(c.strip()) > 50]
    
    if not chunks:
        return 0
        
    ids = []
    documents = []
    metadatas = []
    
    for i, chunk in enumerate(chunks):
        # Création d'un ID unique basé sur le contenu et le nom du fichier
        chunk_id = hashlib.md5(f"{filename}_{i}".encode()).hexdigest()
        ids.append(chunk_id)
        documents.append(chunk)
        metadatas.append({"source": filename})
        
    # Insertion/Mise à jour dans ChromaDB
    collection.upsert(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    return len(documents)

def query_rag(query_text, n_results=3):
    """Recherche les paragraphes les plus pertinents pour une requête donnée."""
    try:
        collection = get_collection()
        # Si la base est vide, on retourne un contexte vide
        if collection.count() == 0:
            return ""
            
        results = collection.query(
            query_texts=[query_text],
            n_results=min(n_results, collection.count())
        )
        
        if not results['documents'] or not results['documents'][0]:
            return ""
            
        context_parts = []
        for i, doc in enumerate(results['documents'][0]):
            source = results['metadatas'][0][i].get('source', 'Inconnu')
            context_parts.append(f"--- Extrait du document : {source} ---\n{doc}")
            
        return "\n\n".join(context_parts)
    except Exception as e:
        print(f"Erreur RAG: {e}")
        return ""

def get_doc_count():
    """Retourne le nombre total de fragments (chunks) indexés."""
    try:
        return get_collection().count()
    except Exception:
        return 0

def clear_db():
    """Vide entièrement la base de connaissances."""
    client = get_chroma_client()
    try:
        client.delete_collection("knowledge_base")
    except Exception:
        pass
