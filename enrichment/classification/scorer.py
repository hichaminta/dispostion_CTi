class PriorityScorer:
    """Calcul de priorité SOC et score de risque additif."""

    @staticmethod
    def calculate_priority(record: dict, threat_type: str):
        """
        Priorité : CRITICAL | HIGH | MEDIUM | LOW
        Action   : escalate | investigate | monitor | block | monitor_quiet

        Signaux utilisés :
          - CVSS score (NVD)
          - vt_malicious_count (toutes sources avec VT)
          - abuseConfidenceScore (feodotracker, cins, phishtank)
          - totalReports (feodotracker, cins)
          - status online/offline (feodotracker)
          - risk_flag high (urlscan - feodotracker, phishtank, openphish, pulsedive, threatfox, urlhaus)
          - confidence threatfox natif
          - intel_downloads (malwarebazaar)
          - typosquat_flag (urlscan)
          - is_compromised (threatfox)
          - suspicious_keywords non vides (urlscan)
        """
        attrs = record.get("attributes", {})

        # --- Extraire les signaux depuis tous les IOCs ---
        max_vt          = 0
        max_abuse       = 0
        max_reports     = 0
        max_tf_conf     = 0
        max_downloads   = 0
        has_online      = False
        has_high_risk   = False
        has_phishing_url = False
        has_typosquat   = False
        has_susp_kw     = False
        has_compromised = False

        for ioc in record.get("iocs", []):
            e = ioc.get("ioc_enrichment", {})

            vt = e.get("vt_malicious_count", e.get("malicious_count", 0)) or 0
            max_vt = max(max_vt, float(vt))

            abuse = e.get("abuseConfidenceScore", 0) or 0
            max_abuse = max(max_abuse, float(abuse))

            reports = e.get("totalReports", 0) or 0
            max_reports = max(max_reports, float(reports))

            tf_conf = e.get("confidence", 0) or 0
            max_tf_conf = max(max_tf_conf, float(tf_conf))

            try:
                dl = int(e.get("intel_downloads", 0) or 0)
                max_downloads = max(max_downloads, dl)
            except:
                pass

            if e.get("status") == "online":
                has_online = True
            if e.get("risk_flag") == "high":
                has_high_risk = True
            if e.get("typosquat_flag") is True:
                has_typosquat = True
            if e.get("suspicious_keywords"):
                has_susp_kw = True
            if e.get("is_compromised") is True:
                has_compromised = True
            if ioc.get("type") == "url" and threat_type == "phishing":
                has_phishing_url = True

        # CVSS pour NVD
        try:
            cvss = float(attrs.get("cvss_score", 0) or 0)
        except:
            cvss = 0

        # EPSS si disponible
        try:
            epss = float(attrs.get("epss", 0) or 0)
        except:
            epss = 0

        # ── Règles de décision (ordre décroissant de sévérité) ──

        # Vulnérabilité critique
        if threat_type == "vulnerability":
            if cvss >= 9.0 or epss >= 0.9:
                return "CRITICAL", "escalate"
            if cvss >= 7.0:
                return "HIGH", "investigate"
            if cvss >= 4.0:
                return "MEDIUM", "monitor"
            return "LOW", "monitor_quiet"

        # Malware actif en ligne + bien détecté
        if threat_type == "malware":
            if has_online and max_vt >= 10:
                return "CRITICAL", "escalate"
            if max_vt >= 50 or (has_online and max_abuse >= 50):
                return "HIGH", "investigate"
            if max_vt >= 10 or max_abuse >= 80 or has_high_risk:
                return "MEDIUM", "monitor"
            if max_vt >= 1 or max_abuse >= 40 or max_reports >= 5:
                return "LOW", "monitor_quiet"
            # malwarebazaar : intel_downloads élevé
            if max_downloads >= 500:
                return "HIGH", "investigate"
            if max_downloads >= 100:
                return "MEDIUM", "monitor"
            return "LOW", "monitor_quiet"

        # Phishing
        if threat_type == "phishing":
            if has_phishing_url and (max_vt >= 5 or has_high_risk):
                return "HIGH", "block"
            if has_phishing_url or has_typosquat or has_susp_kw:
                return "MEDIUM", "block"
            return "LOW", "monitor_quiet"

        # Threatfox confidence natif
        if max_tf_conf >= 90:
            return "HIGH", "investigate"
        if max_tf_conf >= 50:
            return "MEDIUM", "monitor"

        # Compromised host
        if has_compromised:
            return "MEDIUM", "investigate"

        return "LOW", "monitor_quiet"

    @staticmethod
    def calculate_additive_risk(record: dict) -> float:
        """
        Score additif 0-100 pour MISP / dashboard.

        Composantes :
          source_confidence  -> max 25 pts
          vt_malicious_count -> max 25 pts
          abuseConfidenceScore -> max 20 pts
          status online      -> +15 pts
          risk_flag high     -> +10 pts
          typosquat_flag     -> +5 pts
          suspicious_keywords -> +5 pts
          intel_downloads    -> max 10 pts (malwarebazaar)
          tf_confidence      -> max 10 pts
        """
        score = 0.0

        # Source confidence (max 25)
        score += min(25, record.get("source_confidence", 50) * 0.25)

        max_vt      = 0
        max_abuse   = 0
        max_tf_conf = 0
        max_dl      = 0
        bonus = 0

        for ioc in record.get("iocs", []):
            e = ioc.get("ioc_enrichment", {})
            max_vt    = max(max_vt, float(e.get("vt_malicious_count", 0) or 0))
            max_abuse = max(max_abuse, float(e.get("abuseConfidenceScore", 0) or 0))
            max_tf_conf = max(max_tf_conf, float(e.get("confidence", 0) or 0))
            try:
                max_dl = max(max_dl, int(e.get("intel_downloads", 0) or 0))
            except:
                pass
            if e.get("status") == "online":
                bonus += 15
            if e.get("risk_flag") == "high":
                bonus += 10
            if e.get("typosquat_flag") is True:
                bonus += 5
            if e.get("suspicious_keywords"):
                bonus += 5

        # VT detections (max 25)
        if max_vt >= 50:
            score += 25
        elif max_vt >= 10:
            score += 18
        elif max_vt >= 1:
            score += 8

        # AbuseIPDB (max 20)
        score += min(20, max_abuse * 0.2)

        # ThreatFox confidence (max 10)
        score += min(10, max_tf_conf * 0.1)

        # MalwareBazaar downloads (max 10)
        if max_dl >= 500:
            score += 10
        elif max_dl >= 100:
            score += 5

        # Bonus comportementaux
        score += min(35, bonus)

        return round(min(100.0, score), 1)