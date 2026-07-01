import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import sys
from datetime import datetime

# Path to this script's directory for imports
EXTRACTORS_DIR = os.path.dirname(os.path.abspath(__file__))
if EXTRACTORS_DIR not in sys.path:
    sys.path.append(EXTRACTORS_DIR)
from base_extractor import BaseExtractor

SOURCE_NAME = "OTX AlienVault"
# BASE_DIR is one level above EXTRACTORS_DIR
BASE_DIR = os.path.abspath(os.path.join(EXTRACTORS_DIR, "..", ".."))
SOURCE_DIR = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources", "Otx alienvault", "collection")
INPUT_FILE = os.path.join(SOURCE_DIR, "otx_pulses.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources", "Otx alienvault", "extraction")
TRACKING_DIR = os.path.join(EXTRACTORS_DIR, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "alienvault_tracking.json")

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
    
    tracker = None
    try:
        project_root = os.path.abspath(os.path.join(EXTRACTORS_DIR, ".."))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from utils.tracking import ExtractionTracker
        tracker = ExtractionTracker(SOURCE_NAME)
        tracking = tracker.get_tracking()
        
        if not force_full:
            oldest_extracted_at = tracking.get('oldest_extracted_at')
            recent_extracted_at = tracking.get('recent_extracted_at')
    except Exception as e:
        print(f"Error loading Tracker: {e}")


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

    def process_alienvault_item(item):
        import copy
        
        # We start with basic extraction
        clean_item = copy.deepcopy(item)
        
        extracted_iocs = []
        tags = set()
        attrs = {}
        refs = set()
        
        # 1. Base ID
        record_id = str(item.get("id") or item.get("pulse_id", ""))
        
        # 2. Extract explicitly from "indicators" list to avoid NLP/Regex scanning completely
        for ind in item.get("indicators", []):
            ind_type = ind.get("type", "").lower()
            ind_val = ind.get("indicator")
            if not ind_val: continue
            
            mapped_type = extract_type_otx(ind_type)
            if mapped_type:
                # Basic IOC enrichment from indicator specific data
                ioc_enrich = {}
                if ind.get("title"): ioc_enrich["title"] = ind.get("title")
                if ind.get("description"): ioc_enrich["description"] = ind.get("description")
                if ind.get("expiration"): ioc_enrich["expiration"] = ind.get("expiration")
                
                extracted_iocs.append({
                    "type": mapped_type,
                    "value": extractor.normalize_url(ind_val) if mapped_type == 'url' else ind_val.lower().strip(),
                    "source": SOURCE_NAME,
                    "ioc_enrichment": ioc_enrich
                })
                
        # 3. Extract important metadata
        if item.get("tags"):
            for t in item.get("tags", []):
                tags.add(t.lower().strip())
        
        if item.get("targeted_countries"):
            attrs["targeted_countries"] = item.get("targeted_countries")
            
        if item.get("industries"):
            attrs["industries"] = item.get("industries")
            
        if item.get("adversary"):
            attrs["adversary"] = item.get("adversary")
            
        if item.get("tlp"):
            attrs["tlp"] = item.get("tlp")

        if item.get("references"):
            for r in item.get("references", []):
                if r.startswith("http"):
                    refs.add(r.strip())
                    
        # Apply extracted attributes to all IOCs
        for ioc in extracted_iocs:
            for k, v in attrs.items():
                ioc["ioc_enrichment"][k] = v

        # Get dates
        date_fields = ['created', 'modified', 'extracted_at']
        collected_at = None
        for df in date_fields:
            if item.get(df):
                collected_at = item.get(df)
                break

        text_content = []
        if item.get("name"): text_content.append(item.get("name"))
        if item.get("description"): text_content.append(item.get("description"))
        raw_text = " ".join(text_content)

        res = {
            "source": SOURCE_NAME,
            "record_id": record_id,
            "summary": item.get("name", f"Extracted {len(extracted_iocs)} IOCs explicitly from OTX."),
            "raw_text": raw_text,
            "iocs": extracted_iocs,
            "cves": [],
            "tags": sorted(list(tags)),
            "references": sorted(list(refs)),
            "attributes": attrs,
            "collected_at": collected_at
        }
        
        if "description" in item:
            res["description"] = item["description"]
            
        return res

    def extract_type_otx(otx_type):
        otx_type = otx_type.lower()
        if "ipv4" in otx_type or "ipv6" in otx_type: return "ip"
        if "domain" in otx_type or "hostname" in otx_type: return "domaine"
        if "url" in otx_type or "uri" in otx_type: return "url"
        if "md5" in otx_type or "file_hash" in otx_type or "sha" in otx_type: return "hashe"
        if "email" in otx_type: return "autr"
        return None

    for item in new_data:
        res = process_alienvault_item(item)
        new_results.append(res)
        item_ts = res.get('collected_at')
        if item_ts:
            if not current_oldest or item_ts < current_oldest:
                current_oldest = item_ts
            if not current_recent or item_ts > current_recent:
                current_recent = item_ts
            
    # 5. Merge with existing results
    output_path = os.path.join(OUTPUT_DIR, "alienvault_extracted.json")
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
    if tracker:
        try:
            tracker.save_tracking({
                "oldest_extracted_at": current_oldest,
                "recent_extracted_at": current_recent
            })
        except Exception as e:
            print(f"Error saving tracking: {e}")

    
    print(f"Extraction for {SOURCE_NAME} completed. {len(new_results)} items processed. Bounds: {current_oldest} to {current_recent}")

if __name__ == "__main__":
    run_extraction()
