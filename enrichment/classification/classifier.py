
import re

class ThreatClassifier:
    """Identifie le type de menace et effectue un enrichissement profond par mots-clés."""

    @staticmethod
    def infer_threat_type(record, filename):
        """Détermine la catégorie générale (malware, phishing, vulnerability)."""
        source = filename.lower()
        if "nvd" in source or record.get("cves"):
            return "vulnerability"
        if any(s in source for s in ["malware", "threatfox", "abuseipdb", "feodotracker"]):
            return "malware"
        if any(s in source for s in ["openphish", "phishtank", "urlhaus"]):
            return "phishing"
        
        # Analyse des tags si la source est ambigue
        tags = [t.lower() for t in record.get("tags", [])]
        if "malware" in tags or "rat" in tags: return "malware"
        if "phishing" in tags: return "phishing"
        
        return "suspicious"

    @staticmethod
    def classify_attack_type(record, threat_type):
        """Identifie le type spécifique d'attaque (RCE, RAT, Stealer, etc.)."""
        combined_text = (str(record.get("record_id", "")) + " " + 
                         str(record.get("description", "")) + " " + 
                         " ".join(record.get("tags", []))).lower()
        
        if threat_type == "vulnerability":
            maps = {
                "RCE": ["remote code execution", "rce", "execute arbitrary code"],
                "SQLi": ["sql injection", "sqli"],
                "XSS": ["cross-site scripting", "xss"],
                "DoS": ["denial of service", "dos", "ddos"]
            }
        elif threat_type == "malware":
            maps = {
                "RAT": ["rat", "remcos", "njrat", "agenttesla"],
                "Stealer": ["stealer", "redline", "lumma"],
                "Botnet": ["botnet", "mirai", "emotet"],
                "Ransomware": ["ransomware", "encrypt", "lock"]
            }
        else:
            return "Unknown"

        for atype, keywords in maps.items():
            if any(k in combined_text for k in keywords):
                return atype
        return "Other"
