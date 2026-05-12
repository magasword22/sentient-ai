import requests
import json
import os

CONFIG_FILE = "dojo_config.json"

def load_config():
    """Charge la configuration locale pour DefectDojo."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {"url": "", "token": "", "engagement_id": ""}

def save_config(url, token, engagement_id):
    """Sauvegarde la configuration locale."""
    config = {
        "url": url.rstrip('/'),
        "token": token,
        "engagement_id": engagement_id
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
    return True

def push_to_dojo(nuclei_file_path):
    """
    Envoie le fichier JSON généré par Nuclei vers DefectDojo.
    Retourne (True, message) si succès, (False, erreur) sinon.
    """
    config = load_config()
    
    url = config.get("url")
    token = config.get("token")
    engagement_id = config.get("engagement_id")
    
    if not url or not token or not engagement_id:
        return False, "Configuration DefectDojo incomplète. Veuillez configurer l'URL, le Token et l'ID d'engagement dans l'onglet Configuration."
        
    if not os.path.exists(nuclei_file_path):
        return False, f"Fichier de résultats introuvable : {nuclei_file_path}"

    api_endpoint = f"{url}/api/v2/import-scan/"
    
    headers = {
        "Authorization": f"Token {token}"
    }
    
    # Paramètres requis par l'API /import-scan/ de DefectDojo
    data = {
        "scan_type": "Nuclei Scan",
        "engagement": engagement_id,
        "active": "true",
        "verified": "true",
        "minimum_severity": "Info"
    }
    
    try:
        with open(nuclei_file_path, 'rb') as f:
            files = {'file': (os.path.basename(nuclei_file_path), f, 'application/json')}
            response = requests.post(api_endpoint, headers=headers, data=data, files=files, timeout=10)
            
        if response.status_code in [200, 201]:
            resp_data = response.json()
            return True, f"Import réussi ! {resp_data.get('test', 'Test')} créé dans l'engagement {engagement_id}."
        else:
            return False, f"Erreur API ({response.status_code}): {response.text}"
            
    except requests.exceptions.RequestException as e:
        return False, f"Erreur de connexion à DefectDojo : {e}"
