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

def calculate_financial_risk(vulns, sector, company_size, data_sensitivity):
    """
    Calcule le risque financier brut d'une brèche et le ROI de la remédiation.
    Accepts:
        vulns: list of dicts, each having an 'info' dict with 'severity' (or just severity string)
        sector: key from SECTOR_MULTIPLIERS
        company_size: key from COMPANY_SIZE_MULTIPLIERS
        data_sensitivity: key from DATA_SENSITIVITY_MULTIPLIERS
    Returns:
        dict with keys:
            - total_exposure (Risque Brut)
            - total_remediation (Coût de remédiation)
            - net_savings (Économies nettes)
            - roi_pct (Taux de ROI en %)
            - residual_risk (Risque résiduel après remédiation, estimé à 5% du risque initial)
            - detail_list (Liste détaillée des coûts par vulnérabilité)
    """
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
            
        base_breach = BASE_BREACH_COSTS.get(severity, 0.0)
        base_remed = BASE_REMEDIATION_COSTS.get(severity, 0.0)
        
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
            "remediation": remediation
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
        "detail_list": detail_list
    }
