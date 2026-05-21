# -*- coding: utf-8 -*-
"""
Module de calcul du Risque Financier et ROI de la Cybersécurité.
Estime les coûts potentiels d'une brèche de données vs le coût de remédiation.
"""

# Base impact costs per vulnerability severity
BASE_BREACH_COSTS = {
    "critical": 150000.0,
    "high": 60000.0,
    "medium": 15000.0,
    "low": 3000.0
}

# Base remediation costs per vulnerability severity (engineering time, testing, patches)
BASE_REMEDIATION_COSTS = {
    "critical": 4000.0,
    "high": 2000.0,
    "medium": 800.0,
    "low": 200.0
}

# Multipliers
SECTOR_MULTIPLIERS = {
    "Finance / Assurances": 1.5,
    "Santé": 1.8,
    "E-commerce / Retail": 1.3,
    "Technologie / Télécoms": 1.1,
    "Secteur Public": 1.0,
    "Industrie": 1.2,
    "Autre": 1.0
}

COMPANY_SIZE_MULTIPLIERS = {
    "Startup / TPE (< 50 employés)": 0.4,
    "PME (50 - 250 employés)": 1.0,
    "ETI (250 - 5000 employés)": 2.2,
    "Grande Entreprise (> 5000 employés)": 4.5
}

DATA_SENSITIVITY_MULTIPLIERS = {
    "Données Publiques / Faible": 0.7,
    "PII standard (Noms, Emails)": 1.2,
    "Données Financières (CB, Factures)": 1.5,
    "Données Médicales / Sensibilité Haute": 1.7
}

# Justifications and explanations in French
EXPOSURE_JUSTIFICATIONS = {
    "critical": "Impact critique : Risque direct de rançongiciel bloquant l'activité, vol massif de données personnelles ou hautement confidentielles, et sanctions maximales en vertu du RGPD ou de DORA (jusqu'à 20M€ ou 4% du CA mondial). Entraîne des coûts d'investigation forensic d'urgence et une perte de confiance immédiate des partenaires.",
    "high": "Impact élevé : Accès non autorisé à des serveurs contenant des données de production ou d'affaires. Risque d'interruption partielle des opérations, de pénalités contractuelles et de signalement obligatoire de violation aux autorités (CNIL / RGPD, NIS 2).",
    "medium": "Impact modéré : Fuite d'informations sur la structure interne du réseau ou comptes non privilégiés. Risque d'utilisation par des attaquants pour faire de l'élévation de privilèges ou du phishing ciblé.",
    "low": "Impact faible : Divulgation de versions de logiciels, en-têtes HTTP mal configurés. Faible exploitabilité directe mais contribue à la phase de reconnaissance (fingerprinting) d'une attaque plus vaste."
}

REMEDIATION_JUSTIFICATIONS = {
    "critical": "Remédiation urgente : Mobilisation immédiate de ressources d'ingénierie et d'experts externes (cyber-forensics, réponse à incident), déploiement de correctifs hors-cycle (hot patching), réécriture de code de sécurité et tests d'intrusion de validation.",
    "high": "Remédiation prioritaire : Développement et déploiement de patchs de sécurité via les pipelines CI/CD standards, revue de code complète, et validation de non-régression sous 72 heures.",
    "medium": "Remédiation standard : Mise à jour logicielle de routine, modification des règles de pare-feu ou d'accès, et formation rapide des équipes d'exploitation.",
    "low": "Remédiation simple : Correction de fichiers de configuration mineurs, mise à jour de documentation ou simple désactivation d'en-têtes obsolètes."
}

MULTIPLIER_JUSTIFICATIONS = {
    "sector": {
        "Finance / Assurances": "x1.5 : Secteur critique soumis aux contraintes de la réglementation européenne DORA (Digital Operational Resilience Act). Forte attractivité pour les cybercriminels (ciblage monétaire direct).",
        "Santé": "x1.8 : Données de santé (DMP) extrêmement valorisées au marché noir. Réglementation stricte sur l'hébergement de données de santé (HDS) et RGPD. Impact direct sur la continuité des soins et la vie humaine.",
        "E-commerce / Retail": "x1.3 : Fort volume de transactions, dépendance critique au temps de disponibilité (Uptime), et conformité obligatoire au standard PCI-DSS sous peine de lourdes pénalités.",
        "Technologie / Télécoms": "x1.1 : Risque fort d'espionnage industriel, de vol de propriété intellectuelle, d'attaques sur la chaîne d'approvisionnement (Supply Chain) et d'amendes RGPD.",
        "Secteur Public": "x1.0 : Objectif de continuité de service public et obligation de conformité au RGS (Référentiel Général de Sécurité) de l'ANSSI. Impact de souveraineté et d'opinion publique.",
        "Industrie": "x1.2 : Secteur ciblé par la directive NIS 2 (infrastructures critiques / importantes). Risque de paralysie de la chaîne logistique, d'arrêt des chaînes de production (OT) et d'espionnage de brevets.",
        "Autre": "x1.0 : Valeur de base pour les activités commerciales ou de services générales sans sur-réglementation spécifique."
    },
    "company_size": {
        "Startup / TPE (< 50 employés)": "x0.4 : Infrastructure et volume de données plus réduits, mais une attaque peut s'avérer fatale à court terme (dépôt de bilan).",
        "PME (50 - 250 employés)": "x1.0 : Base de référence standard. Structure de gestion cyber intermédiaire, conformité RGPD requise mais tolérance administrative relative.",
        "ETI (250 - 5000 employés)": "x2.2 : Entités souvent classées comme 'importantes' sous la directive NIS 2. Exigences accrues de gouvernance, plans de continuité d'activité (PCA) complexes, et processus internes allongeant les temps de remédiation (+30% sur les coûts d'ingénierie en raison des cycles de validation).",
        "Grande Entreprise (> 5000 employés)": "x4.5 : Entités qualifiées d'essentielles sous NIS 2 / OIV. Exposition maximale, structure de SI fragmentée, et amendes RGPD indexées sur le chiffre d'affaires mondial (jusqu'à 4%). Coûts de remédiation majorés (+80%) en raison de la complexité des validations hiérarchiques et réglementaires."
    },
    "data_sensitivity": {
        "Données Publiques / Faible": "x0.7 : Risque minimal lié à l'image de marque ou à l'indisponibilité du site institutionnel public.",
        "PII standard (Noms, Emails)": "x1.2 : Données personnelles standards protégées par le RGPD. Obligation légale de notification aux personnes concernées et à la CNIL en cas de violation.",
        "Données Financières (CB, Factures)": "x1.5 : Risques d'usurpation d'identité financière, amendes PCI-DSS majeures, et responsabilité civile de l'entreprise engagée.",
        "Données Médicales / Sensibilité Haute": "x1.7 : Données médicales protégées par le secret médical. Les fuites entraînent des poursuites pénales directes, des indemnisations massives et un préjudice moral inestimable."
    }
}

METRIC_EXPLANATIONS = {
    "total_exposure": "Risque Financier Brut : Somme de l'impact théorique estimé d'une brèche réussie pour chaque vulnérabilité détectée. Il intègre le coût de base d'une faille, multiplié par la sévérité et pondéré par le profil de l'entreprise (secteur DORA/NIS 2, taille, sensibilité des données).",
    "total_remediation": "Coût de Remédiation : Représente le coût de mise en œuvre des correctifs (heures de développement, audits de sécurité, tests de régression). Il augmente avec la taille de l'entreprise pour refléter les processus de gouvernance et de déploiement multi-sites.",
    "residual_risk": "Risque Résiduel (5%) : Représente le niveau de risque subsistant après remédiation. En cybersécurité, le risque zéro n'existe pas. Un résidu de 5% est conservé pour couvrir les erreurs humaines, les failles zero-day, ou les dérives de configuration futures.",
    "net_savings": "Économies Nettes (Bénéfice Financier) : Représente la valeur financière nette préservée grâce aux mesures de remédiation, calculée comme : Risque Brut (Exposition) - Coût de Remédiation - Risque Résiduel.",
    "roi_pct": "Taux de ROI Cyber : Mesure l'efficacité économique des dépenses de sécurité cyber. Calculé comme : (Économies Nettes / Coût de Remédiation) * 100. Un taux élevé indique que chaque euro dépensé en remédiation évite un multiple important de pertes potentielles."
}

def calculate_financial_risk(vulns, sector, company_size, data_sensitivity, custom_breach_costs=None, custom_remediation_costs=None):
    """
    Calcule le risque financier brut d'une brèche et le ROI de la remédiation.
    Accepts:
        vulns: list of dicts, each having an 'info' dict with 'severity' (or just severity string)
        sector: key from SECTOR_MULTIPLIERS
        company_size: key from COMPANY_SIZE_MULTIPLIERS
        data_sensitivity: key from DATA_SENSITIVITY_MULTIPLIERS
        custom_breach_costs: dict of custom breach costs (severity -> float)
        custom_remediation_costs: dict of custom remediation costs (severity -> float)
    Returns:
        dict with keys:
            - total_exposure (Risque Brut)
            - total_remediation (Coût de remédiation)
            - net_savings (Économies nettes)
            - roi_pct (Taux de ROI en %)
            - residual_risk (Risque résiduel après remédiation, estimé à 5% du risque initial)
            - detail_list (Liste détaillée des coûts par vulnérabilité)
            - exposure_justifications
            - remediation_justifications
            - multiplier_justifications
            - metric_explanations
            - applied_multipliers
    """
    breach_costs = custom_breach_costs if custom_breach_costs else BASE_BREACH_COSTS
    remediation_costs = custom_remediation_costs if custom_remediation_costs else BASE_REMEDIATION_COSTS

    mult_sector = SECTOR_MULTIPLIERS.get(sector, 1.0)
    mult_size = COMPANY_SIZE_MULTIPLIERS.get(company_size, 1.0)
    mult_sensitivity = DATA_SENSITIVITY_MULTIPLIERS.get(data_sensitivity, 1.0)
    
    overall_multiplier = mult_sector * mult_size * mult_sensitivity
    
    total_exposure = 0.0
    total_remediation = 0.0
    detail_list = []
    
    for v in vulns:
        # Extract severity
        severity = ""
        vuln_name = "Unknown Vulnerability"
        if isinstance(v, dict):
            severity = v.get("info", {}).get("severity", "").lower()
            vuln_name = v.get("info", {}).get("name", "Unknown Vulnerability")
        elif isinstance(v, str):
            severity = v.lower()
            
        if not severity:
            continue
            
        base_breach = breach_costs.get(severity, 0.0)
        base_remed = remediation_costs.get(severity, 0.0)
        
        # Apply multipliers
        exposure = base_breach * overall_multiplier
        remediation = base_remed  # Remediation is not heavily affected by sector, but can be scaled slightly by size
        # scale remediation slightly by size to reflect enterprise overhead
        if company_size == "ETI (250 - 5000 employés)":
            remediation *= 1.3
        elif company_size == "Grande Entreprise (> 5000 employés)":
            remediation *= 1.8
            
        total_exposure += exposure
        total_remediation += remediation
        
        detail_list.append({
            "name": vuln_name,
            "severity": severity,
            "exposure": exposure,
            "remediation": remediation,
            "base_exposure": base_breach,
            "base_remediation": base_remed
        })
        
    residual_risk = total_exposure * 0.05
    net_savings = total_exposure - total_remediation - residual_risk
    if net_savings < 0:
        net_savings = 0.0
        
    roi_pct = 0.0
    if total_remediation > 0:
        roi_pct = (net_savings / total_remediation) * 100.0
        
    return {
        "total_exposure": total_exposure,
        "total_remediation": total_remediation,
        "net_savings": net_savings,
        "roi_pct": roi_pct,
        "residual_risk": residual_risk,
        "detail_list": detail_list,
        "exposure_justifications": EXPOSURE_JUSTIFICATIONS,
        "remediation_justifications": REMEDIATION_JUSTIFICATIONS,
        "multiplier_justifications": MULTIPLIER_JUSTIFICATIONS,
        "metric_explanations": METRIC_EXPLANATIONS,
        "applied_multipliers": {
            "sector": mult_sector,
            "size": mult_size,
            "sensitivity": mult_sensitivity,
            "overall": overall_multiplier
        }
    }
