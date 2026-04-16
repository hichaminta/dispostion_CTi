import os
import json
import logging
import sys
from datetime import datetime

# Parent dir logic for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from nlp.nlp_enricher import NLPEnricher

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Enrichment.feodotracker")

# Paths (Relative to enrichment/nlp/scripts/source_enricher.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
EXTRACTED_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
ENRICHMENT_ROOT = os.path.join(BASE_DIR, "enrichment")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
TRACKING_DIR = os.path.join(ENRICHMENT_ROOT, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "feodotracker_tracking.json")

def ensure_dirs():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)

def filter_by_timestamp(data, oldest_time_str, recent_time_str):
    if not oldest_time_str and not recent_time_str:
        return data
        
    oldest_time = None
    recent_time = None
    
    try:
        if oldest_time_str:
            clean_oldest = oldest_time_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
            oldest_time = datetime.fromisoformat(clean_oldest)
        if recent_time_str:
            clean_recent = recent_time_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
            recent_time = datetime.fromisoformat(clean_recent)
    except:
        return data

    filtered = []
    for item in data:
        ts_str = item.get('collected_at') or item.get('extracted_at') or item.get('last_modified')
        if not ts_str:
            filtered.append(item)
            continue
        
        try:
            clean_ts = ts_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
            item_time = datetime.fromisoformat(clean_ts)
            
            is_outside_range = False
            if oldest_time and item_time < oldest_time:
                is_outside_range = True
            if recent_time and item_time > recent_time:
                is_outside_range = True
            
            if is_outside_range:
                filtered.append(item)
        except:
            filtered.append(item)
            
    return filtered

def merge_enriched_results(existing, new):
    indexed = {item.get("record_id"): item for item in existing if item.get("record_id")}
    for item in new:
        rid = item.get("record_id")
        if rid:
            indexed[rid] = item
        else:
            existing.append(item)
    return list(indexed.values())

def process_source():
    ensure_dirs()
    
    file_path = os.path.join(EXTRACTED_DIR, "feodotracker_extracted.json")
    if not os.path.exists(file_path):
        logger.warning(f"Extracted file not found: {file_path}")
        return

    # Load Unified Tracking
    tracking_data = {"nlp": {}, "geo": {}}
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, 'r', encoding='utf-8') as f:
                tracking_data = json.load(f)
                if "nlp" not in tracking_data: tracking_data["nlp"] = {}
                if "geo" not in tracking_data: tracking_data["geo"] = {}
        except Exception:
            pass

    oldest_extracted_at = tracking_data["nlp"].get("oldest_extracted_at")
    recent_extracted_at = tracking_data["nlp"].get("recent_extracted_at")

    logger.info(f"Checking for new items in: feodotracker_extracted.json")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read {file_path}: {e}")
        return

    # Filter items
    new_items = filter_by_timestamp(data, oldest_extracted_at, recent_extracted_at)
    
    if not new_items:
        logger.info(f"No new items for feodotracker outside tracked range.")
        return

    logger.info(f"Processing {len(new_items)} new items for feodotracker...")
    
    enriched_new = []
    nlp_enricher = NLPEnricher()
    
    current_oldest = oldest_extracted_at
    current_recent = recent_extracted_at

    for item in new_items:
        enriched_item = nlp_enricher.enrich(item)
        enriched_new.append(enriched_item)
        
        # Update bounds
        item_ts = item.get('collected_at') or item.get('extracted_at')
        if item_ts:
            if not current_oldest or item_ts < current_oldest:
                current_oldest = item_ts
            if not current_recent or item_ts > current_recent:
                current_recent = item_ts

    out_file_name = "feodotracker_extracted.json".replace('_extracted.json', '_enriched.json')
    out_file_path = os.path.join(OUTPUT_DIR, out_file_name)
    
    existing_data = []
    if os.path.exists(out_file_path):
        try:
            with open(out_file_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
        except: pass
    
    all_enriched = merge_enriched_results(existing_data, enriched_new)
    
    with open(out_file_path, 'w', encoding='utf-8') as f:
        json.dump(all_enriched, f, indent=4)
        
    logger.info(f"Saved {len(all_enriched)} enriched items to {out_file_path}")
    
    # Save the new bounds in the unified tracking file
    tracking_data["nlp"]["oldest_extracted_at"] = current_oldest
    tracking_data["nlp"]["recent_extracted_at"] = current_recent
    with open(TRACKING_FILE, 'w', encoding='utf-8') as f:
        json.dump(tracking_data, f, indent=4)
        
    # --- STAGE 2: Chain Geolocation Enrichment (Unified) ---
    logger.info("➔ Transitioning to STAGE 2: Geolocation...")
    import subprocess
    geo_script = os.path.join(ENRICHMENT_ROOT, "geolocalisation", "enrichir.py")
    if os.path.exists(geo_script):
        subprocess.run([sys.executable, geo_script, "--source", "feodotracker"], capture_output=False)

if __name__ == "__main__":
    process_source()
