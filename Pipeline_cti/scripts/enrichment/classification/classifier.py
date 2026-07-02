import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
class ThreatClassifier:
    """Classification threat_type + attack_type couvrant toutes les sources CTI."""

    # malware_family connue -> attack_type
    MALWARE_FAMILY_MAP = {
        # Botnets
        "emotet": "Botnet", "qakbot": "Botnet", "trickbot": "Botnet",
        "mirai": "Botnet", "dridex": "Botnet", "necurs": "Botnet",
        "bazarloader": "Botnet", "icedid": "Botnet",
        # RAT
        "remcos": "RAT", "njrat": "RAT", "asyncrat": "RAT",
        "quasar": "RAT", "cobalt strike": "RAT", "havoc": "RAT",
        "metasploit": "RAT", "sliver": "RAT",
        # Stealer
        "agenttesla": "Stealer", "redline": "Stealer", "lumma": "Stealer",
        "formbook": "Stealer", "vidar": "Stealer", "raccoon": "Stealer",
        "unknown stealer": "Stealer",
        # Ransomware
        "lockbit": "Ransomware", "ryuk": "Ransomware", "conti": "Ransomware",
        "blackcat": "Ransomware", "alphv": "Ransomware", "cl0p": "Ransomware",
        # Dropper / Loader
        "loader": "Dropper", "guloader": "Dropper", "smoke loader": "Dropper",
        "bumblebee": "Dropper",
        # Exploit kit
        "rig": "ExploitKit", "magnitude": "ExploitKit",
    }

    # tags malwarebazaar -> attack_type
    MALWAREBAZAAR_TAG_MAP = {
        "mirai": "Botnet", "gafgyt": "Botnet", "mozi": "Botnet",
        "rat": "RAT", "njrat": "RAT", "asyncrat": "RAT",
        "stealer": "Stealer", "formbook": "Stealer",
        "ransomware": "Ransomware", "lockbit": "Ransomware",
        "loader": "Dropper", "dropper": "Dropper",
        "upx": "Packer",
    }

    @staticmethod
    def infer_threat_type(record, filename):
        """DÃ©termine la catÃ©gorie : malware | phishing | vulnerability | suspicious."""
        source = filename.lower()

        if "nvd" in source or record.get("cves"):
            return "vulnerability"

        if any(s in source for s in ["malware", "threatfox", "feodotracker",
                                      "spamhaus", "cins", "abuseipdb"]):
            return "malware"

        if any(s in source for s in ["openphish", "phishtank", "urlhaus"]):
            return "phishing"

        # Pulsedive / alienvault : analyser les tags
        tags = [t.lower() for t in record.get("tags", [])]
        if any(t in tags for t in ["malware", "rat", "botnet", "stealer",
                                    "ransomware", "trojan", "loader"]):
            return "malware"
        if any(t in tags for t in ["phishing", "phish", "credential"]):
            return "phishing"
        if any(t in tags for t in ["cve-", "vulnerability", "exploit", "zero-day"]):
            return "vulnerability"

        # Alienvault : description narrative
        desc = record.get("description", "").lower()
        if any(k in desc for k in ["zero-day", "cve-", "remote code execution",
                                    "privilege escalation", "exploit"]):
            return "vulnerability"
        if any(k in desc for k in ["phishing", "credential", "login page"]):
            return "phishing"
        if any(k in desc for k in ["malware", "botnet", "rat", "stealer",
                                    "ransomware", "backdoor", "trojan"]):
            return "malware"

        # malware_family prÃ©sent dans un IOC
        for ioc in record.get("iocs", []):
            family = ioc.get("ioc_enrichment", {}).get("malware_family", "").lower()
            if family:
                return "malware"

        return "suspicious"

    @staticmethod
    def classify_attack_type(record, threat_type):
        """Identifie l'attack_type prÃ©cis selon la source et les donnÃ©es disponibles."""

        # 1. malware_family dans ioc_enrichment (feodotracker, threatfox)
        for ioc in record.get("iocs", []):
            enrich = ioc.get("ioc_enrichment", {})
            family = enrich.get("malware_family", "").lower().strip()
            if family in ThreatClassifier.MALWARE_FAMILY_MAP:
                return ThreatClassifier.MALWARE_FAMILY_MAP[family]

        # 2. malware_family dans attributes (threatfox, pulsedive)
        attr_family = record.get("attributes", {}).get("malware_family", "").lower().strip()
        if attr_family in ThreatClassifier.MALWARE_FAMILY_MAP:
            return ThreatClassifier.MALWARE_FAMILY_MAP[attr_family]

        # 3. threat_type natif threatfox dans ioc_enrichment
        for ioc in record.get("iocs", []):
            tf_type = ioc.get("ioc_enrichment", {}).get("threat_type", "").lower()
            if tf_type == "botnet_cc":
                return "Botnet"
            if tf_type in ["payload_delivery", "dropper"]:
                return "Dropper"
            if tf_type == "exploit":
                return "Exploit"

        # 4. malwarebazaar : tags + intel_downloads
        if "malwar" in record.get("source", "").lower():
            tags = [t.lower() for t in record.get("tags", [])]
            for tag in tags:
                for key, atype in ThreatClassifier.MALWAREBAZAAR_TAG_MAP.items():
                    if key in tag:
                        return atype
            for ioc in record.get("iocs", []):
                try:
                    if int(ioc.get("ioc_enrichment", {}).get("intel_downloads", 0)) >= 100:
                        return "WidespreadMalware"
                except:
                    pass

        # 5. Fallback : analyse textuelle description + tags
        combined = (
            record.get("description", "") + " " +
            " ".join(record.get("tags", []))
        ).lower()

        if threat_type == "vulnerability":
            maps = {
                "RCE":        ["remote code execution", "rce", "execute arbitrary"],
                "LPE":        ["privilege escalation", "lpe", "local privilege"],
                "SQLi":       ["sql injection", "sqli"],
                "XSS":        ["cross-site scripting", "xss"],
                "SSRF":       ["ssrf", "server-side request"],
                "DoS":        ["denial of service", "dos", "ddos"],
                "AuthBypass": ["authentication bypass", "auth bypass", "unauthenticated"],
                "ZeroDay":    ["zero-day", "0-day", "in the wild"],
            }
        elif threat_type == "malware":
            maps = {
                "RAT":         ["rat", "remote access", "remcos", "asyncrat", "njrat", "cobalt", "havoc"],
                "Stealer":     ["stealer", "redline", "lumma", "formbook", "vidar", "raccoon"],
                "Botnet":      ["botnet", "mirai", "emotet", "qakbot", "trickbot", "c2", "command and control"],
                "Ransomware":  ["ransomware", "encrypt", "lockbit", "ryuk", "conti", "cl0p"],
                "Dropper":     ["dropper", "loader", "downloader", "bumblebee", "guloader"],
                "Wiper":       ["wiper", "destructive", "disk wipe"],
                "Rootkit":     ["rootkit", "kernel", "ring0"],
                "Cryptominer": ["miner", "cryptominer", "xmrig", "monero"],
            }
        elif threat_type == "phishing":
            maps = {
                "Credential": ["login", "password", "credential", "account", "harvest"],
                "BEC":        ["invoice", "wire transfer", "payment", "ceo fraud", "business email"],
                "Smishing":   ["sms", "smishing", "text message"],
                "Spearphish": ["targeted", "spear", "executive"],
            }
        else:
            return "Unknown"

        for atype, keywords in maps.items():
            if any(k in combined for k in keywords):
                return atype

        return "Other"

    @staticmethod
    def get_confidence_label(source_confidence: int) -> str:
        """Score numÃ©rique -> label lisible SOC."""
        if source_confidence >= 90:
            return "HIGH"
        elif source_confidence >= 75:
            return "MEDIUM"
        elif source_confidence >= 50:
            return "LOW"
        else:
            return "UNVERIFIED"