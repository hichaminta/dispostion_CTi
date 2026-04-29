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

class RiskScorer:
    """SOC-ready Additive Risk Scoring Engine."""

    @staticmethod
    def calculate_ioc_score(ioc_data, record_tags, malware_family=None):
        """Calculates additive risk score (0-100) based on SOC priorities."""
        enrichment = ioc_data.get('enrichment', {})
        score = 0
        
        # 1. VirusTotal Ratio Analysis
        vt_malicious = enrichment.get('vt_malicious_count', enrichment.get('malicious_count', 0))
        vt_total = enrichment.get('vt_total_engines', 0)
        if vt_total > 0:
            ratio = (vt_malicious / vt_total) * 100
            if ratio > 50:
                score += 40
            elif ratio >= 10:
                score += 25
        elif vt_malicious > 10: 
            score += 40
        elif vt_malicious > 2:
            score += 25

        # 2. AbuseIPDB Confidence
        abuse_conf = enrichment.get('confidence', enrichment.get('abuse_score', 0))
        if abuse_conf >= 80:
            score += 25
            
        # 3. URLScan Analysis
        if enrichment.get('urlscan_verdict') is True:
            score += 25
        # Note: URLScan score contribution not explicitly in the new list but keep if helpful?
        # User said: "URLScan malicious -> +25"
            
        # 4. Malware Family Context
        if malware_family:
            score += 20
            
        # 5. Risk Flag Contribution
        risk_flag = enrichment.get('risk_flag', 'low').lower()
        if risk_flag == 'high':
            score += 30
        elif risk_flag == 'medium':
            score += 15

        # Final Score Cap
        final_score = min(score, 100)
        level = RiskScorer._get_level(final_score)
        
        # SOC Action for IOCs
        soc_action = "monitor"
        if final_score >= 80: soc_action = "urgent"
        elif final_score >= 60: soc_action = "investigate"
        
        return float(final_score), level, soc_action

    @staticmethod
    def calculate_confidence_score(record, source_list):
        """Calculates a confidence score (0-100) based on source reliability and enrichment."""
        base_confidence = 50.0
        
        # 1. Multi-source consensus
        if len(source_list) > 2:
            base_confidence += 20
        elif len(source_list) == 2:
            base_confidence += 10
            
        # 2. Source reliability (example)
        reliable_sources = ['abuseipdb', 'misp', 'nvd', 'malwarebazaar']
        for src in source_list:
            if any(rs in src.lower() for rs in reliable_sources):
                base_confidence += 5
                break
                
        # 3. Enrichment completeness
        if record.get('ioc_enrichment') or record.get('attributes', {}).get('cvss_score'):
            base_confidence += 15
            
        return min(base_confidence, 100.0)

    @staticmethod
    def classify_cve(description):
        """Classifies CVE into categories based on description keywords and contextual patterns."""
        if not description:
            return "Unknown"
        
        desc = description.lower()
        mapping = {
            "RCE": ["remote code execution", "rce", "execute arbitrary code", "arbitrary code execution", "overflow", "deserialization"],
            "Privilege Escalation": ["privilege escalation", "elevation of privilege", "escalate privileges", "root access", "local privilege"],
            "XSS": ["cross-site scripting", "xss", "inject arbitrary web script"],
            "SQL Injection": ["sql injection", "sqli", "database query injection"],
            "DoS": ["denial of service", "dos", "ddos", "exhaustion", "crash", "infinite loop"],
            "Path Traversal": ["path traversal", "directory traversal", "../"],
            "LFI/RFI": ["local file inclusion", "remote file inclusion", "lfi", "rfi", "include files"]
        }
        
        for attack_type, keywords in mapping.items():
            if any(k in desc for k in keywords):
                return attack_type
        return "Other"

    @staticmethod
    def get_mitre_mapping(attack_type):
        """Maps attack types to multiple MITRE ATT&CK techniques and tactics."""
        mapping = {
            "RCE": {
                "techniques": ["T1203", "T1190"], 
                "tactics": ["Execution", "Initial Access"]
            },
            "Privilege Escalation": {
                "techniques": ["T1068", "T1548"], 
                "tactics": ["Privilege Escalation"]
            },
            "XSS": {
                "techniques": ["T1189", "T1204.001"], 
                "tactics": ["Initial Access"]
            },
            "SQL Injection": {
                "techniques": ["T1190", "T1505"], 
                "tactics": ["Initial Access", "Persistence"]
            },
            "DoS": {
                "techniques": ["T1498", "T1499"], 
                "tactics": ["Impact"]
            },
            "Path Traversal": {
                "techniques": ["T1083", "T1140"], 
                "tactics": ["Discovery", "Defense Evasion"]
            },
            "LFI/RFI": {
                "techniques": ["T1190", "T1213"], 
                "tactics": ["Initial Access", "Collection"]
            }
        }
        res = mapping.get(attack_type, {"techniques": ["Unknown"], "tactics": ["Unknown"]})
        return res

    @staticmethod
    def calculate_cve_score(record):
        """Specific scoring for vulnerabilities with EPSS and Exploitation Status."""
        attributes = record.get('attributes', {})
        cvss = attributes.get('cvss_score', 0)
        desc = attributes.get('description', '').lower()
        
        # 1. Exploitation Status
        exploitation_status = "none"
        if any(k in desc for k in ["exploited in the wild", "active exploitation", "known exploited"]):
            exploitation_status = "known exploited"
        elif any(k in desc for k in ["proof of concept", "poc available", "exploit available"]):
            exploitation_status = "PoC available"
            
        # 2. Simulated EPSS (based on CVSS and status)
        epss_score = (cvss / 10.0) * (1.5 if exploitation_status != "none" else 1.0)
        epss_score = min(epss_score, 0.99)
        
        # 3. Check for malicious IOCs
        has_malicious_ioc = any(
            ioc.get('ioc_enrichment', {}).get('malicious_count', 0) > 0 or 
            ioc.get('ioc_enrichment', {}).get('vt_malicious_count', 0) > 0 
            for ioc in record.get('iocs', [])
        )
        
        # 4. SOC Priority Logic
        # CRITICAL: CVSS >= 9 + exploited + IOC present
        is_critical = (cvss >= 9 and exploitation_status == "known exploited" and has_malicious_ioc)
        
        if is_critical:
            priority = "CRITICAL"
            soc_action = "incident_response"
            base_score = 100.0
        elif cvss >= 9 or (cvss >= 7 and exploitation_status != "none"):
            priority = "CRITICAL" if cvss >= 9 else "HIGH"
            soc_action = "escalate"
            base_score = 90.0 if cvss >= 9 else 80.0
        elif cvss >= 7:
            priority = "HIGH"
            soc_action = "investigate"
            base_score = 75.0
        elif cvss >= 4:
            priority = "MEDIUM"
            soc_action = "monitor"
            base_score = 45.0
        else:
            priority = "LOW"
            soc_action = "monitor"
            base_score = 20.0

        return {
            "score": float(base_score),
            "priority": priority,
            "soc_action": soc_action,
            "epss": epss_score,
            "exploitation_status": exploitation_status,
            "cvss_missing": cvss == 0
        }

    @staticmethod
    def _get_level(score):
        if score >= 81: return "critical"
        if score >= 61: return "high"
        if score >= 31: return "medium"
        return "low"

class ThreatCorrelator:
    """Advanced CTI Orchestrator: Correlation, Grouping, and Validation."""
    
    def __init__(self, input_dir, output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.events = {}
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

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
        files = [f for f in os.listdir(self.input_dir) if f.endswith('.json')]
        
        for filename in files:
            file_path = os.path.join(self.input_dir, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._process_records(data)
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
                # Apply CVE specific metadata
                if cves:
                    cve_id = cves[0] if isinstance(cves[0], str) else cves[0].get('id')
                    cve_res = RiskScorer.calculate_cve_score(record)
                    description = attributes.get('description', '')
                    attack_type = RiskScorer.classify_cve(description)
                    mitre = RiskScorer.get_mitre_mapping(attack_type)
                    
                    self.events[group_id].update({
                        "risk_score": cve_res["score"],
                        "risk_level": cve_res["priority"].lower(),
                        "priority_score": cve_res["priority"],
                        "soc_action": cve_res["soc_action"],
                        "attack_type": attack_type,
                        "threat_context": cve_res["exploitation_status"],
                        "epss": cve_res["epss"],
                        "mitre_techniques": mitre["techniques"],
                        "mitre_tactics": mitre["tactics"]
                    })
                    if cve_res["cvss_missing"]: self.events[group_id]["cvss_missing"] = True
                    
                    # Temporal Correlation: tag "recent_threat" if CVE < 30 days
                    try:
                        cve_year = str(cve_id).split('-')[1]
                        current_year = datetime.now().year
                        if str(cve_year) == str(current_year):
                            self.events[group_id]["tags"].add("recent_threat")
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
            
            # Final Event Score & SOC Actions
            if event["event_type"] == "vulnerability":
                # CVE scores already set in record processing
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

            # Deduplicate relations
            unique_relations = []
            seen_rels = set()
            for rel in event["relations"]:
                rel_id = f"{rel['source']}-{rel['target']}-{rel['type']}"
                if rel_id not in seen_rels:
                    unique_relations.append(rel)
                    seen_rels.add(rel_id)
            event["relations"] = unique_relations
            
            cleaned_events.append(event)
        
        return cleaned_events

    def finalize_and_save(self):
        cleaned_events = self._validate_and_clean()
        
        timestamp_str = datetime.now().strftime('%Y-%m-%d')
        output_file = os.path.join(self.output_dir, f"correlated_events_{timestamp_str}.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_events, f, indent=4)
        
        logger.info(f"Final Report: Generated {len(cleaned_events)} events in {output_file}")

if __name__ == "__main__":
    BASE_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi"
    INPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
    OUTPUT_DIR = os.path.join(BASE_DIR, "output_correlation")
    
    correlator = ThreatCorrelator(INPUT_DIR, OUTPUT_DIR)
    correlator.process_files()
    correlator.finalize_and_save()
