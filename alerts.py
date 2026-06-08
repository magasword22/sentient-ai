import os
import requests
import report_config

def send_webhook_notification(target, hosts_count, vuln_count, report_pdf_path):
    """
    Envoie une notification Slack, Discord, ou Teams suite à la complétion d'un audit de sécurité.
    """
    cfg = report_config.load_report_config()
    webhook_url = cfg.get("webhook_url", "")
    if not webhook_url:
        return
        
    provider = cfg.get("webhook_provider", "Generic")
    
    title = f"🛡️ Sentient AI - Audit terminé : {target}"
    message = (
        f"Un scan de sécurité automatique s'est terminé avec succès.\n"
        f"• **Cible** : `{target}`\n"
        f"• **Hôtes identifiés** : `{hosts_count}`\n"
        f"• **Anomalies relevées** : `{vuln_count}`\n"
        f"• **Livrable** : `{os.path.basename(report_pdf_path)}`"
    )
    
    try:
        if provider == "Slack":
            payload = {
                "text": f"*{title}*\n{message}"
            }
        elif provider == "Discord":
            payload = {
                "content": f"**{title}**\n{message}"
            }
        elif provider == "Teams":
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "7c3aed",
                "summary": title,
                "sections": [{
                    "activityTitle": title,
                    "activitySubtitle": "Rapport d'Audit Automatisé",
                    "facts": [
                        {"name": "Cible", "value": target},
                        {"name": "Hôtes actifs", "value": str(hosts_count)},
                        {"name": "Vulnérabilités", "value": str(vuln_count)},
                        {"name": "Fichier", "value": os.path.basename(report_pdf_path)}
                    ],
                    "markdown": True
                }]
            }
        else: # Generic JSON webhook
            payload = {
                "event": "audit_completed",
                "target": target,
                "hosts_found": hosts_count,
                "vulnerabilities_found": vuln_count,
                "report_file": os.path.basename(report_pdf_path)
            }
            
        r = requests.post(webhook_url, json=payload, timeout=5.0)
        print(f"[+] Webhook ({provider}) envoyé avec succès. Status code: {r.status_code}")
    except Exception as e:
        print(f"[!] Erreur d'envoi du webhook: {e}")
