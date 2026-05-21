import os
import json

CONFIG_FILE = "report_config.json"

def load_report_config():
    """Charge la configuration de personnalisation des rapports."""
    default_config = {
        "company_name": "Sentient AI",
        "primary_color": "#7c3aed",
        "footer_text": "Sentient AI - Rapport d'Audit Automatisé",
        "logo_path": "",
        "sector": "Finance / Assurances",
        "company_size": "PME (50 - 250 employés)",
        "data_sensitivity": "PII standard (Noms, Emails)",
        "custom_breach_costs": {
            "critical": 150000.0,
            "high": 60000.0,
            "medium": 15000.0,
            "low": 3000.0
        },
        "custom_remediation_costs": {
            "critical": 4000.0,
            "high": 2000.0,
            "medium": 800.0,
            "low": 200.0
        }
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # S'assurer que toutes les clés par défaut sont présentes
                for key, val in default_config.items():
                    if key not in config:
                        config[key] = val
                    elif isinstance(val, dict) and isinstance(config[key], dict):
                        # Merge nested dicts (like custom_breach_costs)
                        for subkey, subval in val.items():
                            if subkey not in config[key]:
                                config[key][subkey] = subval
                return config
        except Exception:
            pass
    return default_config

def save_report_config(company_name, primary_color, footer_text, logo_path, sector=None, company_size=None, data_sensitivity=None, custom_breach_costs=None, custom_remediation_costs=None):
    """Enregistre la configuration de personnalisation des rapports."""
    config = {
        "company_name": company_name,
        "primary_color": primary_color,
        "footer_text": footer_text,
        "logo_path": logo_path,
        "sector": sector or "Finance / Assurances",
        "company_size": company_size or "PME (50 - 250 employés)",
        "data_sensitivity": data_sensitivity or "PII standard (Noms, Emails)",
        "custom_breach_costs": custom_breach_costs or {
            "critical": 150000.0,
            "high": 60000.0,
            "medium": 15000.0,
            "low": 3000.0
        },
        "custom_remediation_costs": custom_remediation_costs or {
            "critical": 4000.0,
            "high": 2000.0,
            "medium": 800.0,
            "low": 200.0
        }
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print(f"[!] Erreur de sauvegarde de la config rapport : {e}")
        return False
