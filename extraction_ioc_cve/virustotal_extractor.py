import os
import json
import sys
from datetime import datetime

# Path to this script's directory for imports
EXTRACTORS_DIR = os.path.dirname(os.path.abspath(__file__))
if EXTRACTORS_DIR not in sys.path:
    sys.path.append(EXTRACTORS_DIR)
from base_extractor import BaseExtractor

SOURCE_NAME = "VirusTotal"
# BASE_DIR is one level above EXTRACTORS_DIR
BASE_DIR = os.path.dirname(EXTRACTORS_DIR)
SOURCE_DIR = os.path.join(BASE_DIR, "Sources_data", "VirusTotal")
INPUT_FILE = os.path.join(SOURCE_DIR, "virustotal_data.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
TRACKING_DIR = os.path.join(EXTRACTORS_DIR, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "virustotal_tracking.json")

def run_extraction():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TRACKING_DIR, exist_ok=True)
    extractor = BaseExtractor()
    
    # Check for CLI flags
    force_full = "--full" in sys.argv
    if force_full:
        print(f"[{SOURCE_NAME}] Mode: FORCE FULL (Ignoring tracker)")

    # 1. Load tracking
    oldest_extracted_at = None
    recent_extracted_at = None
    if os.path.exists(TRACKING_FILE) and not force_full:
        try:
            with open(TRACKING_FILE, "r") as f:
                tracking = json.load(f)
                oldest_extracted_at = tracking.get('oldest_extracted_at')
                recent_extracted_at = tracking.get('recent_extracted_at')
                # Migration from old format
                if not recent_extracted_at and tracking.get('last_extracted_at'):
                    recent_extracted_at = tracking.get('last_extracted_at')
                    oldest_extracted_at = tracking.get('last_extracted_at')
        except: pass

    # 2. Load raw data
    if not os.path.exists(INPUT_FILE):
        print(f"Input file {INPUT_FILE} not found.")
        return

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {INPUT_FILE}: {e}")
        return
    
    if not isinstance(data, list):
        data = [data]
        
    # 3. Filter data (process if outside [oldest, recent])
    new_data = extractor.filter_by_timestamp(data, oldest_extracted_at, recent_extracted_at)
    
    if not new_data:
        print(f"No new data for {SOURCE_NAME} outside tracked range [{oldest_extracted_at or 'init'} - {recent_extracted_at or 'init'}].")
        return

    # 4. Process new items
    print(f"Processing {len(new_data)} / {len(data)} items for {SOURCE_NAME}...")
    new_results = []
    
    current_oldest = oldest_extracted_at
    current_recent = recent_extracted_at

    # --- INIT SPACY FOR INTELLIGENT EXTRACTION ---
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        print("SpaCy NLP model loaded perfectly for VirusTotal intelligent extraction.")
    except Exception as e:
        print(f"Warning: SpaCy NLP not fully available ({e}). Using fallback semantic extraction.")
        nlp = None
        
    def process_virustotal_item(item):
        import copy
        import re
        
        clean_item = copy.deepcopy(item)
        extracted_iocs = []
        
        # 1. Base ID is a hash
        record_id = item.get("id")
        if record_id:
            if len(record_id) == 64: extracted_iocs.append({"type": "sha256", "value": record_id})
            elif len(record_id) == 40: extracted_iocs.append({"type": "sha1", "value": record_id})
            elif len(record_id) == 32: extracted_iocs.append({"type": "md5", "value": record_id})
            else: extracted_iocs.append({"type": "hashe", "value": record_id})
            
        # 2. Extract explicit networks
        rels = item.get("relationships", {})
        for ip in rels.get("contacted_ips", []):
            extracted_iocs.append({"type": "ip", "value": ip})
        for dom in rels.get("contacted_domains", []):
            extracted_iocs.append({"type": "domaine", "value": dom})
            
        # 3. NLP Analysis on noisy fields (last_analysis_results)
        nlp_tags = set()
        malware_family = None
        
        attrs = item.get("attributes", {})
        last_analysis = attrs.get("last_analysis_results", {})
        
        # Shield from regex
        if "attributes" in clean_item and "last_analysis_results" in clean_item["attributes"]:
            clean_item["attributes"]["last_analysis_results"] = {}
            
        # Semantic mapping
        common_threats = ["trojan", "ransomware", "worm", "botnet", "spyware", "adware", 
                          "downloader", "dropper", "phishing", "backdoor", "keylogger", 
                          "rootkit", "exploit", "hacktool", "stealer", "miner", "ddos"]
        ignore_words = ["win32", "win64", "generic", "agent", "variant", "gen", "malware", 
                        "application", "suspicious", "kryptik", "heur", "program", "detect",
                        "peexe", "file", "unknown"]
        family_candidates = {}
        
        for av_name, av_result in last_analysis.items():
            if isinstance(av_result, str):
                clean_res = re.sub(r'[^a-zA-Z0-9]', ' ', av_result.lower())
                tokens = clean_res.split()
                
                for token in tokens:
                    if len(token) < 3: continue
                    if any(t in token for t in common_threats):
                        nlp_tags.update([t for t in common_threats if t in token])
                        continue
                    
                    if nlp:
                        doc = nlp(token)
                        if token not in ignore_words and len(token) > 3:
                            family_candidates[token] = family_candidates.get(token, 0) + 1
                    else:
                        if token not in ignore_words and len(token) > 3:
                            family_candidates[token] = family_candidates.get(token, 0) + 1

        if family_candidates:
            sorted_cands = sorted(family_candidates.items(), key=lambda x: x[1], reverse=True)
            malware_family = sorted_cands[0][0]
            nlp_tags.add(malware_family)

        # 4. Standard extraction on CLEANED text
        res = extractor.process_item(SOURCE_NAME, clean_item)
        
        # 5. Merge findings
        existing_iocs = {f"{i['type']}_{i['value']}" for i in res['iocs']}
        for ioc in extracted_iocs:
            key = f"{ioc['type']}_{ioc['value']}"
            if key not in existing_iocs:
                ioc["source"] = SOURCE_NAME
                ioc["ioc_enrichment"] = res.get('attributes', {})
                res['iocs'].append(ioc)
                existing_iocs.add(key)
                
        # Inject NLP tags
        res['tags'] = sorted(list(set(res.get('tags', []) + list(nlp_tags))))
        if malware_family:
            res['attributes']['malware_family'] = malware_family
            for ioc in res['iocs']:
                if "ioc_enrichment" not in ioc: ioc["ioc_enrichment"] = {}
                ioc["ioc_enrichment"]["malware_family"] = malware_family
                
        # Build a meaningful raw_text for NLP instead of a JSON dump
        vt_text_parts = []
        if attrs.get("meaningful_name"):
            vt_text_parts.append(attrs.get("meaningful_name"))
        if attrs.get("type_description"):
            vt_text_parts.append(attrs.get("type_description"))
        if attrs.get("magic"):
            vt_text_parts.append(attrs.get("magic"))
            
        threat_class = attrs.get("popular_threat_classification", {})
        if threat_class and threat_class.get("suggested_threat_label"):
            vt_text_parts.append(threat_class.get("suggested_threat_label"))
            
        # Add crowdsourced YARA descriptions if available
        for yara in attrs.get("crowdsourced_yara_results", []):
            if yara.get("description"):
                vt_text_parts.append(yara.get("description"))

        if vt_text_parts:
            res['raw_text'] = " ".join(vt_text_parts)
        else:
            # Fallback to a partial dump of attributes if no text is found, but avoiding full raw dump
            res['raw_text'] = ""
            
        return res

    for item in new_data:
        res = process_virustotal_item(item)
        new_results.append(res)
        
        # Update bounds
        item_ts = res.get('collected_at')
        if item_ts:
            if not current_oldest or item_ts < current_oldest:
                current_oldest = item_ts
            if not current_recent or item_ts > current_recent:
                current_recent = item_ts
            
    # 5. Merge with existing results
    output_path = os.path.join(OUTPUT_DIR, "virustotal_extracted.json")
    all_results = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                all_results = json.load(f)
        except: pass
    
    # Use merge_results from BaseExtractor to handle deduplication and fusion
    all_results = extractor.merge_results(all_results, new_results, SOURCE_NAME)

    # Save results
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
        
    # 6. Update tracking
    with open(TRACKING_FILE, "w") as f:
        json.dump({
            "oldest_extracted_at": current_oldest,
            "recent_extracted_at": current_recent
        }, f)
    
    print(f"Extraction for {SOURCE_NAME} completed. {len(new_results)} items processed. Bounds: {current_oldest} to {current_recent}")

if __name__ == "__main__":
    run_extraction()
