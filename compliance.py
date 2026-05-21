# -*- coding: utf-8 -*-
"""
Module de conformité réglementaire (Compliance mapping).
Associe les vulnérabilités aux sections de l'ISO 27001, du RGPD, du PCI-DSS et des guides de l'ANSSI.
"""

# Textes de conformité multilingues
COMPLIANCE_TRANSLATIONS = {
    "Français": {
        "credentials": {
            "iso": "ISO 27001 : A.9.4.3 (Gestion des mots de passe) & A.9.2.4 (Gestion des secrets d'authentification)",
            "rgpd": "RGPD : Article 32 (Sécurité du traitement - Contrôle d'accès et authentification forte)",
            "pci": "PCI-DSS v4.0 : Requis 2.1 (Ne pas utiliser les paramètres par défaut du fournisseur) & 8.2 (Authentification des utilisateurs)",
            "anssi": "ANSSI R18 : Gestion des authentifications et politique de mots de passe robustes"
        },
        "exposure": {
            "iso": "ISO 27001 : A.18.1.3 (Protection des enregistrements) & A.12.4 (Journalisation et surveillance)",
            "rgpd": "RGPD : Article 32 (Confidentialité et intégrité des données stockées/exposées)",
            "pci": "PCI-DSS v4.0 : Requis 6.5 (Développement sécurisé d'applications et protection contre les fuites d'informations)",
            "anssi": "ANSSI R39 : Protection du code source et sécurisation des fichiers de configuration sensibles"
        },
        "default": {
            "iso": "ISO 27001 : A.12.6.1 (Gestion des vulnérabilités techniques)",
            "rgpd": "RGPD : Article 32 (Évaluation régulière et application des correctifs de sécurité)",
            "pci": "PCI-DSS v4.0 : Requis 6.2 (Maintien des systèmes à jour et application rapide des correctifs)",
            "anssi": "ANSSI R46 : Gestion des correctifs de sécurité et des vulnérabilités"
        }
    },
    "Anglais": {
        "credentials": {
            "iso": "ISO 27001: A.9.4.3 (Password management systems) & A.9.2.4 (Management of secret authentication information)",
            "rgpd": "GDPR: Article 32 (Security of processing - Access control and strong authentication)",
            "pci": "PCI-DSS v4.0: Requirement 2.1 (Do not use vendor-supplied defaults) & 8.2 (User identification/authentication)",
            "anssi": "ANSSI R18: Management of authentications and robust password policies"
        },
        "exposure": {
            "iso": "ISO 27001: A.18.1.3 (Protection of records) & A.12.4 (Logging and monitoring)",
            "rgpd": "GDPR: Article 32 (Confidentiality and integrity of stored/exposed data)",
            "pci": "PCI-DSS v4.0: Requirement 6.5 (Secure software development and information leak prevention)",
            "anssi": "ANSSI R39: Protection of source code and securing sensitive configuration files"
        },
        "default": {
            "iso": "ISO 27001: A.12.6.1 (Management of technical vulnerabilities)",
            "rgpd": "GDPR: Article 32 (Regular security assessment and patching of systems)",
            "pci": "PCI-DSS v4.0: Requirement 6.2 (Keep systems updated and apply critical security patches)",
            "anssi": "ANSSI R46: Security patch management and vulnerability tracking"
        }
    },
    "Espagnol": {
        "credentials": {
            "iso": "ISO 27001: A.9.4.3 (Sistemas de gestión de contraseñas) y A.9.2.4 (Gestión de información de autenticación secreta)",
            "rgpd": "RGPD: Artículo 32 (Seguridad del tratamiento - Control de acceso y autenticación fuerte)",
            "pci": "PCI-DSS v4.0: Requisito 2.1 (No usar contraseñas por defecto del proveedor) y 8.2 (Autenticación del usuario)",
            "anssi": "ANSSI R18: Gestión de autenticaciones y políticas de contraseñas robustas"
        },
        "exposure": {
            "iso": "ISO 27001: A.18.1.3 (Protección de los registros) y A.12.4 (Registro y supervisión)",
            "rgpd": "RGPD: Artículo 32 (Confidencialidad e integridad de los datos almacenados/expuestos)",
            "pci": "PCI-DSS v4.0: Requisito 6.5 (Desarrollo de software seguro y prevención de fugas de información)",
            "anssi": "ANSSI R39: Protección del código fuente y protección de archivos de configuración sensibles"
        },
        "default": {
            "iso": "ISO 27001: A.12.6.1 (Gestión de vulnerabilidades técnicas)",
            "rgpd": "RGPD: Artículo 32 (Evaluación periódica de la seguridad y aplicación de parches)",
            "pci": "PCI-DSS v4.0: Requisito 6.2 (Mantener sistemas actualizados y aplicar parches de seguridad)",
            "anssi": "ANSSI R46: Gestión de parches de seguridad y seguimiento de vulnerabilidades"
        }
    },
    "Allemand": {
        "credentials": {
            "iso": "ISO 27001: A.9.4.3 (Passwort-Managementsysteme) & A.9.2.4 (Verwaltung von geheimen Authentifizierungsinformationen)",
            "rgpd": "DSGVO: Artikel 32 (Sicherheit der Verarbeitung - Zugriffskontrolle und starke Authentifizierung)",
            "pci": "PCI-DSS v4.0: Anforderung 2.1 (Keine vom Hersteller bereitgestellten Standardwerte verwenden) & 8.2 (Benutzeridentifikation)",
            "anssi": "ANSSI R18: Authentifizierungsverwaltung und robuste Passwortrichtlinien"
        },
        "exposure": {
            "iso": "ISO 27001: A.18.1.3 (Schutz von Aufzeichnungen) & A.12.4 (Protokollierung und Überwachung)",
            "rgpd": "DSGVO: Artikel 32 (Vertraulichkeit und Integrität gespeicherter/exponierter Daten)",
            "pci": "PCI-DSS v4.0: Anforderung 6.5 (Sichere Softwareentwicklung und Vermeidung von Informationslecks)",
            "anssi": "ANSSI R39: Schutz des Quellcodes und Sicherung sensibler Konfigurationsdateien"
        },
        "default": {
            "iso": "ISO 27001: A.12.6.1 (Handhabung von technischen Schwachstellen)",
            "rgpd": "DSGVO: Artikel 32 (Regelmäßige Überprüfung und Einspielen von Sicherheitsupdates)",
            "pci": "PCI-DSS v4.0: Anforderung 6.2 (Systeme auf dem neuesten Stand halten und Sicherheits-Patches einspielen)",
            "anssi": "ANSSI R46: Patch-Management und Schwachstellenverfolgung"
        }
    }
}

def map_vulnerability_to_compliance(vuln_name, template_id, language="Français"):
    """
    Associe une vulnérabilité à ses exigences de conformité.
    Retourne un dictionnaire avec les clés 'iso', 'rgpd', 'pci', 'anssi'.
    """
    # Sélectionner le sous-dictionnaire linguistique
    lang = language if language in COMPLIANCE_TRANSLATIONS else "Français"
    dict_lang = COMPLIANCE_TRANSLATIONS[lang]
    
    vuln_name_lower = str(vuln_name).lower() if vuln_name else ""
    template_id_lower = str(template_id).lower() if template_id else ""
    
    # Détection de la catégorie
    is_credentials = any(word in vuln_name_lower or word in template_id_lower 
                         for word in ["tomcat", "login", "credential", "password", "auth", "identifiant"])
    is_exposure = any(word in vuln_name_lower or word in template_id_lower 
                      for word in ["git", "exposure", "env", "key", "token", "leak", "config", "backup", "exposé"])
    
    if is_credentials:
        return dict_lang["credentials"]
    elif is_exposure:
        return dict_lang["exposure"]
    else:
        return dict_lang["default"]
