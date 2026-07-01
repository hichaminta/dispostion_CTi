import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
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

        # --- Nouveau système : utiliser le score de risque global ---
        risk_score = PriorityScorer.calculate_additive_risk(record)

        # Règle spéciale pour les vulnérabilités (CVSS prime)
        if threat_type == "vulnerability":
            try:
                cvss = float(attrs.get("cvss_score", 0) or 0)
                epss = float(attrs.get("epss", 0) or 0)
            except:
                cvss = epss = 0

            if cvss >= 9.0 or epss >= 0.9:
                return "CRITICAL", "escalate"
            if cvss >= 7.0:
                return "HIGH", "investigate"
            if cvss >= 4.0:
                return "MEDIUM", "monitor"
            return "LOW", "monitor_quiet"

        # Mapping direct du score de risque vers la priorité SOC
        if risk_score >= 80:
            return "CRITICAL", "escalate"
        elif risk_score >= 60:
            return "HIGH", "investigate"
        elif risk_score >= 40:
            return "MEDIUM", "monitor"
        else:
            return "LOW", "monitor_quiet"

    @staticmethod
    def calculate_additive_risk(record: dict) -> float:
        """
        Calcule le score de risque additif 0-100 pour MISP / dashboard.
        Utilise le risque maximal calculé parmi tous les IOCs du record.
        """
        source_conf = record.get("source_confidence", 50)
        iocs = record.get("iocs", [])
        if not iocs:
            return round(min(100.0, source_conf * 0.5), 1)
            
        scores = [PriorityScorer.calculate_ioc_risk(ioc, source_conf) for ioc in iocs]
        return max(scores)

    @staticmethod
    def calculate_ioc_risk(ioc: dict, source_confidence: int = 50) -> float:
        """
        Calcule le score de risque pour UN SEUL IOC selon son type.
        Formules spécifiques pour Hash, IP, URL/Domaine pour atteindre 100%.
        """
        e = ioc.get("ioc_enrichment", {})
        ioc_type = ioc.get("type", "").lower()
        score = 0.0

        # Récupération de la confiance native (ex: ThreatFox)
        tf_conf = float(e.get("confidence", 0) or 0)
        # La confiance de base est le max entre la source_confidence globale et la confiance native
        base_conf = max(source_confidence, tf_conf)

        # Extraction des signaux
        vt = float(e.get("vt_malicious_count", e.get("malicious_count", 0)) or 0)
        abuse = float(e.get("abuseConfidenceScore", 0) or 0)

        try:
            dl = int(e.get("intel_downloads", 0) or 0)
        except:
            dl = 0

        # Type Hash (MD5, SHA1, SHA256)
        if ioc_type in ("sha256", "sha1", "md5", "hash", "hashe"):
            # Confiance source : 40%
            score += (base_conf / 100.0) * 40.0

            if dl > 0:
                # MalwareBazaar : VT 40% + volumétrie 20%
                if vt > 0:
                    score += 20.0 + min(20.0, ((vt - 1) / 49.0) * 20.0)
                if dl >= 500: score += 20
                elif dl >= 100: score += 15
                elif dl >= 10: score += 10
                else: score += 5
            else:
                # Autres sources : VT 60%
                if vt > 0:
                    score += 30.0 + min(30.0, ((vt - 1) / 49.0) * 30.0)
            
        # Type IP
        elif ioc_type in ("ip", "ipv4", "ipv6"):
            # Confiance source : 30%
            score += (base_conf / 100.0) * 30.0
            
            # VirusTotal : 30% (calcul progressif basé sur 50 moteurs)
            if vt > 0:
                score += 15.0 + min(15.0, ((vt - 1) / 49.0) * 15.0)
            
            # AbuseIPDB : 30%
            score += (abuse / 100.0) * 30.0
            
            # Bonus : 10%
            if e.get("status") == "online": score += 5
            if e.get("is_compromised") is True: score += 5
            
        # Type URL / Domaine
        elif ioc_type in ("url", "domaine", "domain"):
            # Confiance source : 30%
            score += (base_conf / 100.0) * 30.0
            
            # VirusTotal : 30% (calcul progressif basé sur 50 moteurs)
            if vt > 0:
                score += 15.0 + min(15.0, ((vt - 1) / 49.0) * 15.0)
            
            # URLScan : 30%
            urlscan_score = 0
            if e.get("risk_flag") == "high": urlscan_score += 15
            elif e.get("risk_flag") == "medium": urlscan_score += 5
            
            if e.get("typosquat_flag") is True: urlscan_score += 10
            if e.get("suspicious_keywords"): urlscan_score += 5
            
            score += min(30.0, urlscan_score)
            
            # Bonus : 10%
            if e.get("status") == "online": score += 10
            
        # Fallback pour autres types
        else:
            score += (base_conf / 100.0) * 50.0
            # VirusTotal : 50% (calcul progressif basé sur 50 moteurs)
            if vt > 0:
                score += 25.0 + min(25.0, ((vt - 1) / 49.0) * 25.0)

        # Pénalité stricte pour faux positifs (ex: URLs Malpedia)
        vt_harmless = float(e.get("vt_harmless_count", e.get("harmless_count", 0)) or 0)
        if vt == 0 and vt_harmless > 20:
            score = score * 0.25  # Divise le score par 4 (ex: passe de 30 à 7.5)

        return round(min(100.0, score), 1)