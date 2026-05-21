import os
import json

CONFIG_FILE = "report_config.json"

def load_report_config():
    """Charge la configuration de personnalisation des rapports."""
    default_config = {
        "company_name": "Sentient AI",
        "primary_color": "#7c3aed",
        "footer_text": "Sentient AI - Rapport d'Audit Automatisé",
        "logo_path": ""
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # S'assurer que toutes les clés par défaut sont présentes
                for key, val in default_config.items():
                    if key not in config:
                        config[key] = val
                return config
        except Exception:
            pass
    return default_config

def save_report_config(company_name, primary_color, footer_text, logo_path):
    """Enregistre la configuration de personnalisation des rapports."""
    config = {
        "company_name": company_name,
        "primary_color": primary_color,
        "footer_text": footer_text,
        "logo_path": logo_path
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"[!] Erreur de sauvegarde de la config rapport : {e}")
        return False
