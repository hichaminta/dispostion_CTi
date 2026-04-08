import os
import json
import sys
from datetime import datetime

# Path to this script's directory for imports
EXTRACTORS_DIR = os.path.dirname(os.path.abspath(__file__))
if EXTRACTORS_DIR not in sys.path:
    sys.path.append(EXTRACTORS_DIR)
from base_extractor import BaseExtractor

SOURCE_NAME = "OpenPhish"
# BASE_DIR is one level above EXTRACTORS_DIR
BASE_DIR = os.path.dirname(EXTRACTORS_DIR)
SOURCE_DIR = os.path.join(BASE_DIR, "Sources_data", "OpenPhish")
INPUT_FILE = os.path.join(SOURCE_DIR, "openphish_data.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
TRACKING_DIR = os.path.join(EXTRACTORS_DIR, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "openphish_tracking.json")

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

    for item in new_data:
        res = extractor.process_item(SOURCE_NAME, item)
        new_results.append(res)
        
        # Update bounds
        item_ts = res.get('collected_at')
        if item_ts:
            if not current_oldest or item_ts < current_oldest:
                current_oldest = item_ts
            if not current_recent or item_ts > current_recent:
                current_recent = item_ts
            
    # 5. Merge with existing results
    output_path = os.path.join(OUTPUT_DIR, "openphish_extracted.json")
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
