import json
import os
import re
import logging
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Classification_Enrichment")

# Path adjustment: script is in enrichment/classification/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

class IntelligenceClassifier:
    """Refines and classifies enriched CTI records before correlation."""
    
    def __init__(self, enrichment_dir):
        self.enrichment_dir = enrichment_dir
        self.stats = {
            "total_files": 0,
            "total_records": 0,
            "modified_records": 0,
            "priority": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "skipped_records": 0
        }

    def run(self, source_filter=None, skip_enriched=False):
        if not os.path.exists(self.enrichment_dir):
            logger.error(f"Enrichment directory not found: {self.enrichment_dir}")
            return

        all_files = [f for f in os.listdir(self.enrichment_dir) if f.endswith("_enriched.json")]
        
        if source_filter:
            # Special Fix: 'Unified Extraction' means process all files
            if source_filter.lower() == "unified extraction":
                json_files = all_files
                logger.info(f"### GLOBAL RUN: Unified Extraction Mode ###")
            else:
                json_files = [f for f in all_files if source_filter.lower() in f.lower()]
                if not json_files:
                    logger.warning(f"No files found matching source filter: {source_filter}")
                    return
                logger.info(f"### FILTERED RUN: Source '{source_filter}' ###")
        else:
            json_files = all_files
            logger.info("### GLOBAL CLASSIFICATION & SCORING STARTED ###")

        self.stats["total_files"] = len(json_files)
        
        for filename in json_files:
            filepath = os.path.join(self.enrichment_dir, filename)
            logger.info(f"Processing {filename}...")
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    records = json.load(f)
            except Exception as e:
                logger.error(f"Failed to read {filename}: {e}")
                continue

            if not isinstance(records, list):
                continue

            modified = False
            for record in records:
                # Skip if already enriched and flag is set
                if skip_enriched and "soc_enriched" in record.get("tags", []):
                    self.stats["skipped_records"] += 1
                    continue

                original_state = json.dumps(record, sort_keys=True)
                
                # 1. Infer Threat Type
                threat_type = self._infer_threat_type(record, filename)
                
                # 2. Apply Specific Enrichment
                if threat_type == "vulnerability":
                    self._enrich_vulnerability(record)
                elif threat_type == "malware":
                    self._enrich_malware(record)
                elif threat_type == "phishing":
                    self._enrich_phishing(record)
                elif threat_type == "suspicious":
                    self._enrich_infrastructure(record)
                
                # 3. Global Priority and Context
                self._apply_global_logic(record, threat_type)
                
                if json.dumps(record, sort_keys=True) != original_state:
                    modified = True
                    self.stats["modified_records"] += 1
                
                self.stats["total_records"] += 1
                priority = record.get("priority_score", "LOW").upper()
                self.stats["priority"][priority] = self.stats["priority"].get(priority, 0) + 1

            if modified:
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(records, f, indent=4, ensure_ascii=False)
                    logger.info(f"[OK] {filename} updated with classification labels.")
                except Exception as e:
                    logger.error(f"Failed to write {filename}: {e}")

        self._print_summary()

    def _infer_threat_type(self, record, filename):
        """Infers the general category of the threat."""
        source = filename.lower()
        if "nvd" in source or record.get("cves"):
            return "vulnerability"
        if any(s in source for s in ["malware", "threatfox", "abuseipdb", "feodotracker"]):
            return "malware"
        if any(s in source for s in ["openphish", "phishtank", "urlhaus"]):
            return "phishing"
        
        # Fallback based on content
        tags = [t.lower() for t in record.get("tags", [])]
        if "malware" in tags or "rat" in tags: return "malware"
        if "phishing" in tags: return "phishing"
        
        return "suspicious"

    def _enrich_vulnerability(self, record):
        """Deep enrichment for CVEs."""
        name = record.get("record_id", "")
        desc = record.get("description", "")
        tags_list = list(record.get("tags", []))
        
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
        
        record["attack_type"] = found_type
        
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
            record["mitre_techniques"] = mitre_map[found_type][0]
            record["mitre_tactics"] = mitre_map[found_type][1]
            if "mitre_mapped" not in record.get("tags", []):
                record.setdefault("tags", []).append("mitre_mapped")

    def _enrich_malware(self, record):
        """Enrichment for Malware records."""
        tags = [t.lower() for t in record.get("tags", [])]
        ioc_enrichments = [ioc.get("ioc_enrichment", {}) for ioc in record.get("iocs", [])]
        
        combined_tags = " ".join(tags)
        for enrich in ioc_enrichments:
            combined_tags += " " + str(enrich.get("vt_tags", ""))
            combined_tags += " " + str(enrich.get("malware_family", ""))
            
        combined_tags = combined_tags.lower()
        
        malware_types = {
            "RAT": ["rat", "remcos", "nanocore", "agenttesla", "njrat", "quasarrat", "remote access"],
            "Botnet": ["botnet", "mirai", "mozi", "emotet", "cobalt strike"],
            "Stealer": ["stealer", "redline", "lumma", "vidar", "raccoon", "credential stealer"],
            "Downloader": ["downloader", "guploader", "smoke loader"],
            "Loader": ["loader", "buer loader", "hancitor"],
            "PowerShell malware": ["powershell", "ps1", "encodedcommand"],
            "Persistence malware": ["persistence", "startup", "registry key", "service creation"]
        }
        
        found_type = record.get("attack_type", "Malware")
        if found_type in ["Unknown", "Other"]: found_type = "Malware"
        
        for mtype, keywords in malware_types.items():
            if any(k in combined_tags for k in keywords):
                found_type = mtype
                break
        
        record["attack_type"] = found_type
        
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
            record["mitre_techniques"] = mitre_map[found_type][0]
            record["mitre_tactics"] = mitre_map[found_type][1]
            if "mitre_mapped" not in record.get("tags", []):
                record.setdefault("tags", []).append("mitre_mapped")

    def _enrich_phishing(self, record):
        """Enrichment for Phishing records."""
        record["attack_type"] = "Phishing"
        record["mitre_techniques"] = ["T1566"]
        record["mitre_tactics"] = ["Initial Access"]
        if "phishing" not in record.get("tags", []):
            record.setdefault("tags", []).append("phishing")

    def _enrich_infrastructure(self, record):
        """Enrichment for Suspicious Infrastructure."""
        record["threat_context"] = "suspicious infrastructure"
        if "infrastructure" not in record.get("tags", []):
            record.setdefault("tags", []).append("infrastructure")

    def _apply_global_logic(self, record, event_type):
        """Refined priority and context logic."""
        risk_score = record.get("attributes", {}).get("cvss_score", record.get("attributes", {}).get("risk_score", 0))
        epss = record.get("attributes", {}).get("epss", 0)
        
        max_vt_count = 0
        has_phishing_url = False
        for ioc in record.get("iocs", []):
            enrich = ioc.get("ioc_enrichment", {})
            vt_count = enrich.get("vt_malicious_count", enrich.get("malicious_count", 0))
            if isinstance(vt_count, int):
                max_vt_count = max(max_vt_count, vt_count)
            if ioc.get("type") == "url" and event_type == "phishing":
                has_phishing_url = True

        # 1. Priority Logic
        try:
            risk_val = float(risk_score)
            epss_val = float(epss)
        except (ValueError, TypeError):
            risk_val = 0
            epss_val = 0

        if (event_type == "vulnerability" and (risk_val >= 9.0 or epss_val >= 0.9)):
            record["priority_score"] = "CRITICAL"
            record["soc_action"] = "escalate"
        elif (event_type == "malware" and max_vt_count >= 50):
            record["priority_score"] = "HIGH"
            record["soc_action"] = "investigate"
        elif (event_type == "malware" and max_vt_count >= 10):
            record["priority_score"] = "MEDIUM"
        elif has_phishing_url:
            record["priority_score"] = "MEDIUM"
        else:
            record["priority_score"] = record.get("priority_score", "LOW")

        # 2. Threat Context
        if event_type == "vulnerability":
            if epss_val >= 0.9:
                record["threat_context"] = "high exploitation probability"
        elif event_type == "malware":
            if max_vt_count >= 50:
                record["threat_context"] = "confirmed malicious sample"
        elif event_type == "phishing":
            record["threat_context"] = "potential credential theft"
            
        # Tag for enriched
        if "soc_enriched" not in record.get("tags", []):
            record.setdefault("tags", []).append("soc_enriched")

    def _print_summary(self):
        print("\n" + "="*40)
        print(" INTELLIGENCE CLASSIFICATION ")
        print("="*40)
        print(f"Files processed:      {self.stats['total_files']}")
        print(f"Records processed:    {self.stats['total_records']}")
        print(f"Records modified:     {self.stats['modified_records']}")
        print(f"Records skipped:      {self.stats['skipped_records']}")
        print("-"*40)
        print("Priority Distribution:")
        for p, count in sorted(self.stats["priority"].items()):
            print(f"  - {p:10}: {count}")
        print("="*40 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Intelligence Classification & Scoring Engine")
    parser.add_argument("-s", "--source", help="Only process a specific source (e.g. feodotracker)")
    parser.add_argument("--skip-enriched", action="store_true", help="Skip records that already have the 'soc_enriched' tag")
    args = parser.parse_args()
    
    classifier = IntelligenceClassifier(ENRICHMENT_DIR)
    classifier.run(source_filter=args.source, skip_enriched=args.skip_enriched)
