import os
import json
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EventGenerator")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NORM_DIR = os.path.join(BASE_DIR, "output_normaliser")
MISP_OUTPUT_DIR = os.path.join(BASE_DIR, "output_misp")

if not os.path.exists(MISP_OUTPUT_DIR):
    os.makedirs(MISP_OUTPUT_DIR)

# Mapping internal types to MISP types
TYPE_MAPPING = {
    "ip": "ip-dst",
    "domaine": "domain",
    "url": "url",
    "hashe": "hash", 
    "sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "email": "email-src"
}

def get_misp_type(internal_type, value):
    if internal_type == "hashe":
        vlen = len(value)
        if vlen == 32: return "md5"
        if vlen == 40: return "sha1"
        if vlen == 64: return "sha256"
        return "hash"
    return TYPE_MAPPING.get(internal_type, "other")

def generate_events(source_filter=None):
    # Find latest normalization run
    if not os.path.exists(NORM_DIR):
        logger.error(f"Normalization directory {NORM_DIR} not found.")
        return

    runs = [d for d in os.listdir(NORM_DIR) if d.startswith("run_") and os.path.isdir(os.path.join(NORM_DIR, d))]
    if not runs:
        logger.error("No normalization runs found.")
        return
    
    latest_run = sorted(runs)[-1]
    run_path = os.path.join(NORM_DIR, latest_run)
    logger.info(f"Using latest normalization run: {latest_run}")

    files = [f for f in os.listdir(run_path) if f.endswith("_normalized.json")]
    if source_filter:
        files = [f for f in files if source_filter.lower() in f.lower()]
    
    if not files:
        logger.warning("No normalized files found to process.")
        return

    # Create MISP output run folder
    run_ts = datetime.now().strftime("%Y_%m_%d_%H%M%S")
    misp_run_folder = os.path.join(MISP_OUTPUT_DIR, f"misp_run_{run_ts}")
    os.makedirs(misp_run_folder)

    for filename in files:
        source_name = filename.replace("_normalized.json", "")
        file_path = os.path.join(run_path, filename)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            logger.info(f"Generating events for {source_name} ({len(records)} records)...")
            
            # Group records by date
            daily_events = {}
            
            for record in records:
                # Extract date
                ts_str = record.get("collected_at") or record.get("standardized_at")
                try:
                    date_str = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).strftime("%Y-%m-%d")
                except:
                    date_str = datetime.now().strftime("%Y-%m-%d")
                
                if date_str not in daily_events:
                    daily_events[date_str] = {
                        "info": f"CTI Source: {source_name.capitalize()} - {date_str}",
                        "date": date_str,
                        "Attribute": []
                    }
                
                # Add attributes directly to the Event
                for ioc in record.get("iocs", []):
                    m_type = get_misp_type(ioc.get("type"), ioc.get("value"))
                    attr = {
                        "type": m_type,
                        "value": ioc.get("value"),
                        "comment": f"RecordID: {record.get('record_id')} | Role: {ioc.get('type')}",
                        "Tag": [{"name": t} for t in record.get("tags", [])]
                    }
                    daily_events[date_str]["Attribute"].append(attr)
                    
                    # Add references as separate attributes
                    for ref in record.get("references", []):
                        daily_events[date_str]["Attribute"].append({
                            "type": "link",
                            "value": ref,
                            "comment": f"RecordID: {record.get('record_id')} | External Reference"
                        })

            # Save events to files
            src_output_dir = os.path.join(misp_run_folder, source_name)
            os.makedirs(src_output_dir)
            
            for date_str, event_data in daily_events.items():
                output_file = os.path.join(src_output_dir, f"event_{date_str}.json")
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump({"Event": event_data}, f, indent=4)
                logger.info(f"  [OK] Created event for {date_str} in {output_file}")

        except Exception as e:
            logger.error(f"Failed to generate events for {filename}: {e}")

    logger.info(f"### EVENT GENERATION COMPLETED: {misp_run_folder} ###")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MISP events from normalized data")
    parser.add_argument("-s", "--source", help="Only process a specific source")
    args = parser.parse_args()
    generate_events(source_filter=args.source)
