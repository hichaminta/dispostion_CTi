import json
import os
import re
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SOC_PostProcess")

class SOCEnricher:
    """Refines and fixes enrichment for correlated CTI events."""
    
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.stats = {
            "total": 0,
            "changed": 0,
            "unknown_remaining": 0,
            "mitre_mapped": 0,
            "priority": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }

    def run(self):
        if not os.path.exists(self.input_file):
            logger.error(f"Input file not found: {self.input_file}")
            return

        with open(self.input_file, 'r', encoding='utf-8') as f:
            events = json.load(f)

        logger.info(f"Processing {len(events)} events...")
        self.stats["total"] = len(events)
        
        enriched_events = []
        for event in events:
            # Create a shallow copy to check for changes
            original_state = json.dumps(event, sort_keys=True)
            
            event_type = event.get("event_type", "suspicious").lower()
            
            if event_type == "vulnerability":
                self._enrich_vulnerability(event)
            elif event_type == "malware":
                self._enrich_malware(event)
            elif event_type == "phishing":
                self._enrich_phishing(event)
            elif event_type == "suspicious" or "infrastructure" in event.get("threat_type", ""):
                self._enrich_infrastructure(event)
            
            # Global Priority and Context overrides
            self._apply_global_logic(event)
            
            # Tracking stats
            if json.dumps(event, sort_keys=True) != original_state:
                self.stats["changed"] += 1
            
            if event.get("attack_type") == "Unknown":
                self.stats["unknown_remaining"] += 1
            
            if event.get("mitre_techniques") and "Unknown" not in event["mitre_techniques"]:
                self.stats["mitre_mapped"] += 1
                
            priority = event.get("priority_score", "LOW").upper()
            self.stats["priority"][priority] = self.stats["priority"].get(priority, 0) + 1
            
            enriched_events.append(event)

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(enriched_events, f, indent=4)
            
        logger.info(f"Enrichment complete. Saved to {self.output_file}")
        self._print_summary()

    def _enrich_vulnerability(self, event):
        """Deep enrichment for CVEs."""
        name = event.get("event_name", "")
        # Extract description and tags from IOCs
        desc = ""
        tags_list = list(event.get("tags", []))
        
        for ioc in event.get("iocs", []):
            if ioc.get("type") == "cve" or "CVE-" in str(ioc.get("value")):
                desc += " " + ioc.get("enrichment", {}).get("description", "")
        
        combined_text = (name + " " + desc + " " + " ".join(tags_list)).lower()
        
        # Classification
        classification_map = {
            "RCE": ["remote code execution", "rce", "execute arbitrary code", "arbitrary code execution", "overflow", "deserialization"],
            "Privilege Escalation": ["privilege escalation", "elevation of privilege", "escalate privileges", "root access", "local privilege"],
            "XSS": ["cross-site scripting", "xss", "inject arbitrary web script"],
            "SQL Injection": ["sql injection", "sqli", "database query injection"],
            "DoS": ["denial of service", "dos", "ddos", "exhaustion", "crash", "infinite loop"],
            "Path Traversal": ["path traversal", "directory traversal", "../"],
            "Authentication Bypass": ["authentication bypass", "bypass authentication", "unauthorized access", "broken access control"],
            "Information Disclosure": ["information disclosure", "sensitive information", "data leak", "read arbitrary files"]
        }
        
        found_type = "Unknown"
        for attack_type, keywords in classification_map.items():
            if any(k in combined_text for k in keywords):
                found_type = attack_type
                break
        
        event["attack_type"] = found_type
        
        # MITRE Mapping
        mitre_map = {
            "RCE": (["T1203", "T1190"], ["Initial Access", "Execution"]),
            "Privilege Escalation": (["T1068"], ["Privilege Escalation"]),
            "XSS": (["T1189"], ["Initial Access"]),
            "SQL Injection": (["T1190"], ["Initial Access"]),
            "DoS": (["T1499"], ["Impact"]),
            "Path Traversal": (["T1005"], ["Collection"]),
            "Authentication Bypass": (["T1556"], ["Credential Access", "Defense Evasion"]),
            "Information Disclosure": (["T1005"], ["Collection"])
        }
        
        if found_type in mitre_map:
            event["mitre_techniques"] = mitre_map[found_type][0]
            event["mitre_tactics"] = mitre_map[found_type][1]
            if "mitre_mapped" not in event.get("tags", []):
                event.get("tags", []).append("mitre_mapped")

    def _enrich_malware(self, event):
        """Enrichment for Malware samples."""
        tags = [t.lower() for t in event.get("tags", [])]
        ioc_enrichments = [ioc.get("enrichment", {}) for ioc in event.get("iocs", [])]
        
        combined_tags = " ".join(tags)
        for enrich in ioc_enrichments:
            combined_tags += " " + str(enrich.get("vt_tags", ""))
            combined_tags += " " + str(enrich.get("malware_family", ""))
            
        combined_tags = combined_tags.lower()
        
        # Malware Type Inference
        malware_types = {
            "RAT": ["rat", "remcos", "nanocore", "agenttesla", "njrat", "quasarrat", "remote access"],
            "Botnet": ["botnet", "mirai", "mozi", "emotet", "cobalt strike"],
            "Stealer": ["stealer", "redline", "lumma", "vidar", "raccoon", "credential stealer"],
            "Downloader": ["downloader", "guploader", "smoke loader"],
            "Loader": ["loader", "buer loader", "hancitor"],
            "PowerShell malware": ["powershell", "ps1", "encodedcommand"],
            "Persistence malware": ["persistence", "startup", "registry key", "service creation"]
        }
        
        found_type = event.get("attack_type", "Malware")
        if found_type in ["Unknown", "Other"]: found_type = "Malware"
        
        for mtype, keywords in malware_types.items():
            if any(k in combined_tags for k in keywords):
                found_type = mtype
                break
        
        event["attack_type"] = found_type
        
        # MITRE Mapping
        mitre_map = {
            "RAT": (["T1219", "T1105"], ["Command and Control"]),
            "Botnet": (["T1105", "T1071"], ["Command and Control"]),
            "Stealer": (["T1005", "T1056"], ["Collection", "Credential Access"]),
            "PowerShell malware": (["T1059.001"], ["Execution"]),
            "Persistence malware": (["T1547"], ["Persistence"]),
            "Downloader": (["T1105"], ["Command and Control"]),
            "Loader": (["T1105"], ["Command and Control"])
        }
        
        if found_type in mitre_map:
            event["mitre_techniques"] = mitre_map[found_type][0]
            event["mitre_tactics"] = mitre_map[found_type][1]
            if "mitre_mapped" not in event.get("tags", []):
                event.get("tags", []).append("mitre_mapped")
            
        # Specific tags
        if "rat" in combined_tags and "rat" not in event.get("tags", []): event.get("tags", []).append("rat")
        if "powershell" in combined_tags and "powershell" not in event.get("tags", []): event.get("tags", []).append("powershell")
        if "persistence" in combined_tags and "persistence" not in event.get("tags", []): event.get("tags", []).append("persistence")

    def _enrich_phishing(self, event):
        """Enrichment for Phishing campaigns."""
        event["attack_type"] = "Phishing"
        event["mitre_techniques"] = ["T1566"]
        event["mitre_tactics"] = ["Initial Access"]
        if "phishing" not in event.get("tags", []):
            event.get("tags", []).append("phishing")
        if "mitre_mapped" not in event.get("tags", []):
            event.get("tags", []).append("mitre_mapped")

    def _enrich_infrastructure(self, event):
        """Enrichment for Suspicious Infrastructure."""
        event["threat_context"] = "suspicious infrastructure"
        if "infrastructure" not in event.get("tags", []):
            event.get("tags", []).append("infrastructure")

    def _apply_global_logic(self, event):
        """Refined priority and context logic."""
        event_type = event.get("event_type", "").lower()
        risk_score = event.get("risk_score", 0)
        epss = event.get("epss", 0)
        
        # Gather VT info from IOCs
        max_vt_count = 0
        has_phishing_url = False
        for ioc in event.get("iocs", []):
            vt_count = ioc.get("enrichment", {}).get("vt_malicious_count", ioc.get("enrichment", {}).get("malicious_count", 0))
            if isinstance(vt_count, int):
                max_vt_count = max(max_vt_count, vt_count)
            if ioc.get("type") == "url" and event_type == "phishing":
                has_phishing_url = True

        # 1. Priority Logic
        if (event_type == "vulnerability" and (risk_score >= 90 or epss >= 0.9)):
            event["priority_score"] = "CRITICAL"
            event["soc_action"] = "escalate"
            if "critical_cve" not in event.get("tags", []):
                event.get("tags", []).append("critical_cve")
        elif (event_type == "malware" and max_vt_count >= 50):
            event["priority_score"] = "HIGH"
            event["soc_action"] = "investigate"
            if "high_confidence_malware" not in event.get("tags", []):
                event.get("tags", []).append("high_confidence_malware")
        elif (event_type == "malware" and max_vt_count >= 10):
            event["priority_score"] = "MEDIUM"
            event["soc_action"] = "investigate"
        elif has_phishing_url:
            event["priority_score"] = "MEDIUM"
            event["soc_action"] = "investigate"
            
        # 2. Threat Context
        if event_type == "vulnerability":
            if epss >= 0.9:
                event["threat_context"] = "high exploitation probability"
        elif event_type == "malware":
            if max_vt_count >= 50:
                event["threat_context"] = "confirmed malicious sample"
            elif event.get("attack_type") == "RAT":
                event["threat_context"] = "remote access trojan activity"
        elif event_type == "phishing":
            event["threat_context"] = "credential theft / social engineering"
            
        # Tag for enriched
        if "soc_enriched" not in event.get("tags", []):
            event.get("tags", []).append("soc_enriched")

    def _print_summary(self):
        print("\n" + "="*40)
        print(" SOC ENRICHMENT SUMMARY ")
        print("="*40)
        print(f"Total events processed:        {self.stats['total']}")
        print(f"Number of events changed:      {self.stats['changed']}")
        print(f"Unknown attack_type remaining: {self.stats['unknown_remaining']}")
        print(f"Number of MITRE mapped events: {self.stats['mitre_mapped']}")
        print("-"*40)
        print("Priority Distribution:")
        for p, count in sorted(self.stats["priority"].items()):
            print(f"  - {p:10}: {count}")
        print("="*40 + "\n")

if __name__ == "__main__":
    # Correction of paths to be relative to the workspace root or use BASE_DIR
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
    
    INPUT_FILE = os.path.join(BASE_DIR, "output_correlation", "correlated_events_2026-04-29.json")
    OUTPUT_FILE = os.path.join(BASE_DIR, "output_correlation", "correlated_events_soc_enriched.json")
    
    enricher = SOCEnricher(INPUT_FILE, OUTPUT_FILE)
    enricher.run()
