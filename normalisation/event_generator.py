import os
import json
import logging
import argparse
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EventGenerator")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NORM_DIR = os.path.join(BASE_DIR, "output_normaliser")
MISP_OUTPUT_DIR = os.path.join(BASE_DIR, "output_misp")

if not os.path.exists(MISP_OUTPUT_DIR):
    os.makedirs(MISP_OUTPUT_DIR)

TRACKING_DIR = os.path.join(BASE_DIR, "normalisation", "tracking_events")
if not os.path.exists(TRACKING_DIR):
    os.makedirs(TRACKING_DIR)

def load_source_tracking(source):
    path = os.path.join(TRACKING_DIR, f"{source}_events_tracking.json")
    default_tracking = {
        "latest_indicator_date": "1970-01-01 00:00:00",
        "last_run": None,
        "last_sync_success": None
    }
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key in default_tracking:
                    if key not in data:
                        data[key] = default_tracking[key]
                return data
        except Exception as e:
            logger.error(f"Error loading event tracking for {source}: {e}")
            return default_tracking
    return default_tracking

def save_source_tracking(source, data):
    path = os.path.join(TRACKING_DIR, f"{source}_events_tracking.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving event tracking for {source}: {e}")

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
    # Priority 1: output_enrichment (to take ALL enrichment information as requested)
    ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")
    
    if os.path.exists(ENRICHMENT_DIR) and any(f.endswith(".json") for f in os.listdir(ENRICHMENT_DIR)):
        run_path = ENRICHMENT_DIR
        logger.info(f"Using enrichment data as primary input: {run_path}")
        files = [f for f in os.listdir(run_path) if f.endswith("_enriched.json")]
    else:
        # Fallback to output_normaliser
        if not os.path.exists(NORM_DIR):
            logger.error(f"Normalization directory {NORM_DIR} not found.")
            return

        runs = [d for d in os.listdir(NORM_DIR) if d.startswith("run_") and os.path.isdir(os.path.join(NORM_DIR, d))]
        if not runs:
            logger.error("No normalization runs found.")
            return
        
        latest_run = sorted(runs)[-1]
        run_path = os.path.join(NORM_DIR, latest_run)
        logger.info(f"Falling back to latest normalization run: {latest_run}")
        files = [f for f in os.listdir(run_path) if f.endswith("_normalized.json")]
    
    if source_filter:
        files = [f for f in files if source_filter.lower() in f.lower()]
    
    if not files:
        logger.warning("No files found to process.")
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
            
            source_tracking = load_source_tracking(source_name.lower())
            latest_indicator_date_str = source_tracking.get("latest_indicator_date", "1970-01-01 00:00:00")
            
            try:
                latest_indicator_date = datetime.fromisoformat(latest_indicator_date_str.replace(' ', 'T')).replace(tzinfo=timezone.utc)
            except:
                latest_indicator_date = datetime(1970, 1, 1, tzinfo=timezone.utc)

            current_latest_date = latest_indicator_date
            new_records_count = 0
            
            logger.info(f"Generating events for {source_name} ({len(records)} records)...")
            
            # Group records by date
            daily_events = {}
            
            for record in records:
                # Extract date
                ts_str = record.get("collected_at") or record.get("standardized_at")
                try:
                    record_date = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if record_date.tzinfo is None:
                        record_date = record_date.replace(tzinfo=timezone.utc)
                    
                    if record_date <= latest_indicator_date:
                        continue
                    date_str = record_date.strftime("%Y-%m-%d")
                    if record_date > current_latest_date:
                        current_latest_date = record_date
                except:
                    continue
                
                if date_str not in daily_events:
                    daily_events[date_str] = {
                        "info": f"CTI Source: {source_name.capitalize()} - {date_str}",
                        "date": date_str,
                        "Attribute": []
                    }
                
                # Add attributes directly to the Event
                for ioc in record.get("iocs", []):
                    m_type = get_misp_type(ioc.get("type"), ioc.get("value"))
                    enrichment = ioc.get("ioc_enrichment", {})
                    
                    # Capture Tags from enrichment
                    tags = [{"name": t} for t in record.get("tags", [])]
                    if enrichment.get("malware_family"):
                        tags.append({"name": f"malware:{enrichment['malware_family'].lower()}"})
                    if enrichment.get("threat_type"):
                        tags.append({"name": f"threat:{enrichment['threat_type'].lower()}"})
                    if enrichment.get("risk_flag"):
                        tags.append({"name": f"risk:{enrichment['risk_flag'].lower()}"})

                    # Build detailed comment
                    meta_parts = []
                    meta_parts.append(f"RecordID: {record.get('record_id')}")
                    if enrichment.get("asn"): meta_parts.append(f"ASN: {enrichment['asn']}")
                    if enrichment.get("country"): meta_parts.append(f"Country: {enrichment['country']}")
                    if enrichment.get("status"): meta_parts.append(f"Status: {enrichment['status']}")
                    if enrichment.get("vt_score"): meta_parts.append(f"VT Score: {enrichment['vt_score']}")
                    
                    attr = {
                        "type": m_type,
                        "value": ioc.get("value"),
                        "comment": " | ".join(meta_parts),
                        "Tag": tags
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
                new_records_count += 1

            if new_records_count > 0:
                source_tracking["latest_indicator_date"] = current_latest_date.strftime("%Y-%m-%d %H:%M:%S")
                source_tracking["last_run"] = datetime.now().isoformat()
                source_tracking["last_sync_success"] = datetime.now().isoformat()
                save_source_tracking(source_name.lower(), source_tracking)

        except Exception as e:
            logger.error(f"Failed to generate events for {filename}: {e}")

    logger.info(f"### EVENT GENERATION COMPLETED: {misp_run_folder} ###")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MISP events from normalized data")
    parser.add_argument("-s", "--source", help="Only process a specific source")
    args = parser.parse_args()
    generate_events(source_filter=args.source)
