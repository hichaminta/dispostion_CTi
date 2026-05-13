import os
import json
import re
import logging
from datetime import datetime
from urllib.parse import urlparse
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CorrelationPreMISP")

class IOCCorrector:
    """Standardizes IOC types and values based on patterns."""
    
    IP_REGEX = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    MD5_REGEX = r'^[a-fA-F0-9]{32}$'
    SHA1_REGEX = r'^[a-fA-F0-9]{40}$'
    SHA256_REGEX = r'^[a-fA-F0-9]{64}$'
    CVE_REGEX = r'^CVE-\d{4}-\d{4,7}$'

    @staticmethod
    def fix_type(value, current_type):
        value = str(value).strip()
        if value.lower().startswith(('http://', 'https://')):
            return "url"
        if re.match(IOCCorrector.IP_REGEX, value):
            return "ip"
        if re.match(IOCCorrector.MD5_REGEX, value):
            return "md5"
        if re.match(IOCCorrector.SHA1_REGEX, value):
            return "sha1"
        if re.match(IOCCorrector.SHA256_REGEX, value):
            return "sha256"
        if re.match(IOCCorrector.CVE_REGEX, value.upper()):
            return "cve"
        if current_type in ["domain", "domaine", "hostname"]:
            return "domain"
        return current_type

    @staticmethod
    def normalize_url(url):
        """Standardizes URL format (lowercase, removes redundant trailing slash)."""
        if not url: return url
        url = url.strip().lower()
        if url.endswith('/'):
            parsed = urlparse(url)
            if parsed.path == '/':
                return url.rstrip('/')
        return url


class ThreatCorrelator:
    """Advanced CTI Orchestrator: Correlation, Grouping, and Validation."""
    
    def __init__(self, input_dir, output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.tracking_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "correlation_tracking.json")
        self.processed_files = self._load_tracking()
        self.events = {}
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        self._load_existing_events()

    def _load_tracking(self):
        if os.path.exists(self.tracking_file):
            try:
                with open(self.tracking_file, 'r') as f:
                    return set(json.load(f))
            except:
                return set()
        return set()

    def _save_tracking(self):
        with open(self.tracking_file, 'w') as f:
            json.dump(list(self.processed_files), f, indent=4)

    def _load_existing_events(self):
        """Loads previously correlated events to allow incremental updates."""
        output_file = os.path.join(self.output_dir, "correlated_events_soc_enriched.json")
        if not os.path.exists(output_file):
            return

        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for event in data:
                    group_id = event.get("group_id")
                    if not group_id: continue
                    
                    # Convert lists back to sets for merging
                    event["tags"] = set(event.get("tags", []))
                    event["source_list"] = set(event.get("source_list", []))
                    
                    # Convert IOC list back to dict
                    ioc_dict = {}
                    for ioc in event.get("iocs", []):
                        val = ioc["value"]
                        ioc["sources"] = set(ioc.get("sources", []))
                        ioc["relations"] = set(ioc.get("relations", []))
                        ioc_dict[val] = ioc
                    event["iocs"] = ioc_dict
                    
                    self.events[group_id] = event
            logger.info(f"Loaded {len(self.events)} existing events for incremental update.")
        except Exception as e:
            logger.error(f"Error loading existing events: {e}")

    def extract_brand(self, attributes):
        """Extract brand name for phishing grouping."""
        title = str(attributes.get('urlscan_page_title', attributes.get('page_title', ''))).lower()
        brands = ['facebook', 'dropbox', 'docusign', 'microsoft', 'google', 'apple', 'netflix', 'amazon', 'paypal', 'outlook', 'linkedin', 'adobe', 'binance', 'metamask', 'ledger']
        for brand in brands:
            if brand in title:
                return brand.capitalize()
        return None

    def get_domain_from_url(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else None
        except:
            return None

    def process_files(self):
        logger.info("Phase 1: Loading and Grouping Data...")
        all_files = [f for f in os.listdir(self.input_dir) if f.endswith('.json')]
        new_files = [f for f in all_files if f not in self.processed_files]
        
        if not new_files:
            logger.info("No new files to process.")
            return

        for filename in new_files:
            file_path = os.path.join(self.input_dir, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._process_records(data)
                self.processed_files.add(filename)
            except Exception as e:
                logger.error(f"Error loading {filename}: {str(e)}")

    def _process_records(self, records):
        for record in records:
            source = record.get('source', 'Unknown')
            attributes = record.get('attributes', {})
            collected_at = record.get('collected_at', datetime.now().isoformat())
            date_str = collected_at.split('T')[0]
            
            # --- Targeted Grouping Logic ---
            cves = record.get('cves', [])
            malware_family = attributes.get('malware_family') or next((t for t in record.get('tags', []) if t.lower() in ['clearfake', 'mozi', 'lumma', 'redline', 'stealer', 'remcos', 'nanocore']), None)
            
            group_id = None
            event_meta = {"name": "", "type": "", "threat_type": ""}
            
            # 1. CVE Grouping
            if cves:
                cve_id = cves[0] if isinstance(cves[0], str) else cves[0].get('id')
                group_id = f"CVE-{cve_id}"
                event_meta = {"name": f"Vulnerability - {cve_id}", "type": "vulnerability", "threat_type": "exploit"}

            # 2. MalwareBazaar Sample Grouping
            elif source.lower() == 'malwarebazaar community api':
                sample_id = attributes.get('collect_id') or attributes.get('sha256_hash') or record.get('record_id')
                group_id = f"MB-{sample_id}"
                event_meta = {"name": f"Malware Sample - {sample_id}", "type": "malware", "threat_type": "payload_delivery"}

            # 3. Malware Family Grouping (ThreatFox, Feodo, etc.)
            elif malware_family:
                group_id = f"MAL-{malware_family.upper()}"
                event_meta = {"name": f"Malware - {malware_family}", "type": "malware", "threat_type": "payload_delivery"}

            # 4. Phishing Campaign Grouping
            elif source.lower() in ['openphish', 'phishtank']:
                brand = self.extract_brand(attributes)
                domain = ""
                if record.get('iocs'):
                    domain = self.get_domain_from_url(record['iocs'][0].get('value'))
                
                label = brand if brand else (domain if domain else "Unknown")
                group_id = f"PHISH-{label}-{date_str}"
                event_meta = {"name": f"Phishing Campaign - {label} - {date_str}", "type": "phishing", "threat_type": "social_engineering"}

            # 5. Infrastructure Grouping
            elif source.lower() in ['abuseipdb', 'spamhaus', 'cins army']:
                country = attributes.get('country', 'Unknown')
                group_id = f"INFRA-{source.upper()}-{country}"
                event_meta = {"name": f"Suspicious Infrastructure - {source} - {country}", "type": "suspicious", "threat_type": "infrastructure"}

            # 6. Fallback
            else:
                group_id = f"GEN-{source.upper()}-{date_str}"
                event_meta = {"name": f"Suspicious Activity - {source}", "type": "suspicious", "threat_type": "related"}

            if group_id not in self.events:
                self.events[group_id] = {
                    "event_name": event_meta["name"],
                    "event_type": event_meta["type"],
                    "threat_type": event_meta["threat_type"],
                    "risk_score": 0.0,
                    "risk_level": "low",
                    "priority_score": "LOW",
                    "confidence_score": 0.0,
                    "soc_action": "monitor",
                    "attack_type": "Unknown",
                    "threat_context": "none",
                    "epss": 0.0,
                    "mitre_techniques": [],
                    "mitre_tactics": [],
                    "iocs": {},
                    "relations": [],
                    "tags": set(),
                    "source_list": set(),
                    "first_seen": collected_at,
                    "last_seen": collected_at
                }
                # Apply Inherited Metadata (from output_enrichment)
                new_event = self.events[group_id]
                new_event["priority_score"] = record.get("priority_score", "LOW")
                new_event["attack_type"] = record.get("attack_type", "Unknown")
                
                # Merge MITRE data from record
                for m_item in record.get("mitre_attack", []):
                    if m_item["id"] not in new_event["mitre_techniques"]:
                        new_event["mitre_techniques"].append(m_item["id"])
                    
                # Temporal Correlation: tag "recent_threat" if CVE < 30 days
                try:
                    cve_year = str(cve_id).split('-')[1]
                    current_year = datetime.now().year
                    if str(cve_year) == str(current_year):
                        new_event["tags"].add("recent_threat")
                except: pass

            event = self.events[group_id]
            
            event = self.events[group_id]
            event["last_seen"] = max(event["last_seen"], collected_at)
            event["source_list"].add(source)
            for tag in record.get('tags', []):
                event["tags"].add(tag)

            # --- IOC Processing & Relationship Graphing ---
            sha256_val = None
            if source.lower() == 'malwarebazaar community api':
                sha256_val = attributes.get('sha256_hash') or next((i.get('value') for i in record.get('iocs', []) if i.get('type') == 'sha256'), None)

            for ioc_entry in record.get('iocs', []):
                val = ioc_entry.get('value')
                typ = IOCCorrector.fix_type(val, ioc_entry.get('type'))
                
                if typ == 'url':
                    val = IOCCorrector.normalize_url(val)
                
                enrichment = ioc_entry.get('ioc_enrichment', {})
                relation = enrichment.get('threat_type', 'related')

                # Link Relationship Logic
                if typ == 'url':
                    domain = self.get_domain_from_url(val)
                    if domain:
                        self._add_ioc(group_id, domain, 'domain', 'url_contains_domain', source, enrichment, collected_at, record)
                        self._add_relation(group_id, val, domain, 'url_contains_domain')
                        
                        ip = enrichment.get('ip') or enrichment.get('urlscan_ip') or attributes.get('ip')
                        if ip:
                            self._add_ioc(group_id, ip, 'ip', 'resolves_to', source, enrichment, collected_at, record)
                            self._add_relation(group_id, domain, ip, 'resolves_to')
                
                elif typ == 'domain':
                    ip = enrichment.get('ip') or enrichment.get('urlscan_ip') or attributes.get('ip')
                    if ip:
                        self._add_ioc(group_id, ip, 'ip', 'resolves_to', source, enrichment, collected_at, record)
                        self._add_relation(group_id, val, ip, 'resolves_to')

                # MalwareBazaar Hash Links
                if sha256_val and typ in ['md5', 'sha1', 'imphash', 'tlsh', 'ssdeep'] and val != sha256_val:
                    self._add_relation(group_id, sha256_val, val, "same_file_sample")

                # CVE-IOC Correlation Link
                if cves:
                    cve_id = cves[0] if isinstance(cves[0], str) else cves[0].get('id')
                    cve_ref = f"CVE-{cve_id}"
                    if typ in ['ip', 'domain', 'url']:
                        self._add_relation(group_id, cve_ref, val, "exploits")
                        self.events[group_id]["tags"].add("potential_exploitation_chain")
                    elif typ in ['md5', 'sha1', 'sha256']:
                        self._add_relation(group_id, val, cve_ref, "targets")

                self._add_ioc(group_id, val, typ, relation, source, enrichment, collected_at, record)

    def _add_ioc(self, group_id, value, ioc_type, relation, source, enrichment, timestamp, record):
        """Deduplicated IOC storage with individual scoring."""
        event_iocs = self.events[group_id]["iocs"]
        
        if value not in event_iocs:
            event_iocs[value] = {
                "type": ioc_type,
                "value": value,
                "relations": set(),
                "sources": set(),
                "enrichment": {},
                "risk_score": 0.0,
                "risk_level": "low",
                "first_seen": timestamp,
                "last_seen": timestamp
            }
        
        ioc = event_iocs[value]
        ioc["sources"].add(source)
        ioc["relations"].add(relation)
        ioc["last_seen"] = max(ioc["last_seen"], timestamp)
        
        if enrichment:
            ioc["enrichment"].update(enrichment)

        # Calculate/Update IOC-level score
        malware_family = record.get('attributes', {}).get('malware_family')
        score, level, soc_action = RiskScorer.calculate_ioc_score(ioc, record.get('tags', []), malware_family)
        if score > ioc["risk_score"]:
            ioc["risk_score"] = score
            ioc["risk_level"] = level
            ioc["soc_action"] = soc_action

    def _add_relation(self, group_id, source, target, rel_type):
        """Adds a unique relationship to the event."""
        if not source or not target: return
        rel = {"source": source, "target": target, "type": rel_type}
        if rel not in self.events[group_id]["relations"]:
            self.events[group_id]["relations"].append(rel)

    def _validate_and_clean(self):
        """Final cleanup and event-level score aggregation with correlation bonus."""
        logger.info("Phase 2: Cleaning and Validating Events...")
        cleaned_events = []
        for group_id, event in self.events.items():
            # 1. Filter out empty events
            if not event["iocs"] and event["event_type"] != "vulnerability":
                continue
            if event["event_type"] == "phishing" and not event["iocs"]:
                continue

            # 2. Check for correlation bonus (Multiple types: IP + Domain + Malware/Url)
            ioc_types = {ioc["type"] for ioc in event["iocs"].values()}
            has_ip = 'ip' in ioc_types
            has_domain = 'domain' in ioc_types
            has_malware = any(t in ioc_types for t in ['md5', 'sha1', 'sha256']) or event["event_type"] == 'malware'
            
            bonus = 0
            if has_ip and has_domain and has_malware:
                bonus = 20
                event["tags"].add("correlated_attack")

            # 3. Aggregation and set conversion
            event["source_list"] = sorted(list(event["source_list"]))
            event["tags"] = sorted(list(event["tags"]))
            
            ioc_list = []
            max_ioc_score = 0
            
            for val, ioc_data in event["iocs"].items():
                ioc_data["sources"] = sorted(list(ioc_data["sources"]))
                ioc_data["relations"] = sorted(list(ioc_data["relations"]))
                ioc_list.append(ioc_data)
                if ioc_data["risk_score"] > max_ioc_score:
                    max_ioc_score = ioc_data["risk_score"]

            event["iocs"] = ioc_list
            
            # 4. Threat Context Enrichment
            has_cve = any(ioc["type"] == "cve" for ioc in ioc_list) or event["event_type"] == "vulnerability"
            if has_cve and has_malware and len(ioc_list) > 2:
                event["tags"].add("active_exploitation")

            # 5. Correlation Strength & Diversity
            entity_diversity = len({ioc["type"] for ioc in ioc_list})
            event["correlation_strength"] = len(event["relations"]) * (1.5 if entity_diversity > 1 else 1.0)
            
            # 6. Confidence Score
            event["confidence_score"] = RiskScorer.calculate_confidence_score(event, event["source_list"])
            
            # 7. Advanced Attack Classification (Not in output_enrichment)
            if event["attack_type"] == "Unknown":
                event["attack_type"] = RiskScorer.infer_attack_type(event["event_type"], event["tags"], event["iocs"])
            
            # 8. MITRE Bonus (Inherited + Inferred)
            bonus_techs = RiskScorer.get_mitre_bonus(event["attack_type"])
            for bt in bonus_techs:
                if bt not in event["mitre_techniques"]:
                    event["mitre_techniques"].append(bt)

            # Final Event Score & SOC Actions
            if event["event_type"] == "vulnerability":
                pass
            else:
                # Bonus for CVE presence in non-vulnerability event
                cve_bonus = 20 if has_cve else 0
                event["risk_score"] = min(max_ioc_score + bonus + cve_bonus, 100)
                
                # False Positive Reduction Logic
                if event["confidence_score"] < 60:
                    event["risk_score"] *= 0.8
                if not event["iocs"] and event["event_type"] != "vulnerability":
                    event["risk_score"] *= 0.5
                
                event["risk_level"] = RiskScorer._get_level(event["risk_score"])
                
                # Event-level SOC Action
                score = event["risk_score"]
                if score >= 90:
                    event["priority_score"] = "CRITICAL"
                    event["soc_action"] = "incident_response" if has_cve and has_malware else "escalate"
                elif score >= 70:
                    event["priority_score"] = "HIGH"
                    event["soc_action"] = "investigate"
                elif score >= 40:
                    event["priority_score"] = "MEDIUM"
                    event["soc_action"] = "monitor"
                else:
                    event["priority_score"] = "LOW"
                    event["soc_action"] = "monitor"
            
            # Final Tag
            tags_set = event["tags"] if isinstance(event["tags"], set) else set(event["tags"])
            if "soc_enriched" not in tags_set:
                tags_set.add("soc_enriched")
            event["tags"] = tags_set

            # Store group_id for future re-loading
            event["group_id"] = group_id

            # Deduplicate relations
            unique_relations = []
            seen_rels = set()
            for rel in event["relations"]:
                rel_id = f"{rel['source']}-{rel['target']}-{rel['type']}"
                if rel_id not in seen_rels:
                    unique_relations.append(rel)
                    seen_rels.add(rel_id)
            event["relations"] = unique_relations
            
            # Final set conversion for JSON serializability
            event["tags"] = sorted(list(event["tags"]))
            event["source_list"] = sorted(list(event["source_list"]))
            
            cleaned_events.append(event)
        
        return cleaned_events

    def finalize_and_save(self):
        if not self.events:
            logger.info("No events to save.")
            return

        cleaned_events = self._validate_and_clean()
        
        output_file = os.path.join(self.output_dir, "correlated_events_soc_enriched.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_events, f, indent=4)
        
        self._save_tracking()
        logger.info(f"Final Report: Generated {len(cleaned_events)} events in {output_file}")

if __name__ == "__main__":
    BASE_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi"
    INPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
    OUTPUT_DIR = os.path.join(BASE_DIR, "output_correlation")
    
    correlator = ThreatCorrelator(INPUT_DIR, OUTPUT_DIR)
    correlator.process_files()
    correlator.finalize_and_save()
