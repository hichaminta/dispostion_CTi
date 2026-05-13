
class PriorityScorer:
    """Moteur de calcul de priorité et de score de risque."""

    @staticmethod
    def calculate_priority(record, threat_type):
        """Détermine le niveau de priorité SOC (CRITICAL, HIGH, MEDIUM, LOW)."""
        risk_score = record.get("attributes", {}).get("cvss_score", record.get("attributes", {}).get("risk_score", 0))
        epss = record.get("attributes", {}).get("epss", 0)
        
        # Récupération du max malicious count depuis les IOCs enrichis
        max_vt_count = 0
        has_phishing_url = False
        for ioc in record.get("iocs", []):
            enrich = ioc.get("ioc_enrichment", {})
            vt_count = enrich.get("vt_malicious_count", enrich.get("malicious_count", 0))
            if isinstance(vt_count, (int, float)):
                max_vt_count = max(max_vt_count, vt_count)
            if ioc.get("type") == "url" and threat_type == "phishing":
                has_phishing_url = True

        # Logique de décision
        try:
            risk_val = float(risk_score)
            epss_val = float(epss)
        except:
            risk_val = 0
            epss_val = 0

        if threat_type == "vulnerability" and (risk_val >= 9.0 or epss_val >= 0.9):
            return "CRITICAL", "escalate"
        elif threat_type == "malware" and max_vt_count >= 50:
            return "HIGH", "investigate"
        elif threat_type == "malware" and max_vt_count >= 10:
            return "MEDIUM", "monitor"
        elif has_phishing_url:
            return "MEDIUM", "block"
        
        return "LOW", "monitor_quiet"

    @staticmethod
    def calculate_additive_risk(record):
        """Calcule un score de risque additif (0-100) pour MISP."""
        score = 0
        # Basé sur la fiabilité de la source
        score += (record.get("source_confidence", 50) / 2)
        
        # Basé sur les détections VT
        max_vt = 0
        for ioc in record.get("iocs", []):
            max_vt = max(max_vt, ioc.get("ioc_enrichment", {}).get("vt_malicious_count", 0))
        
        if max_vt >= 50: score += 40
        elif max_vt >= 10: score += 20
        
        return min(100, score)
