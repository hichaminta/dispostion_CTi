import os
import json
import logging
import argparse
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Standardizer")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")
NORM_OUTPUT_DIR = os.path.join(BASE_DIR, "output_normaliser")
TRACKING_DIR = os.path.join(BASE_DIR, "normalisation", "tracking")

# Ensure directories exist
for d in [NORM_OUTPUT_DIR, TRACKING_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

def load_source_tracking(source):
    path = os.path.join(TRACKING_DIR, f"{source}_tracking.json")
    default_tracking = {
        "latest_indicator_date": "1970-01-01 00:00:00",
        "last_run": None,
        "last_sync_success": None
    }
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Ensure all required keys exist
                for key in default_tracking:
                    if key not in data:
                        data[key] = default_tracking[key]
                return data
        except Exception as e:
            logger.error(f"Error loading tracking for {source}: {e}")
            return default_tracking
    return default_tracking

def save_source_tracking(source, data):
    path = os.path.join(TRACKING_DIR, f"{source}_tracking.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving tracking for {source}: {e}")

def standardize(source_filter=None):
    if not os.path.exists(ENRICHMENT_DIR):
        logger.error(f"Enrichment directory {ENRICHMENT_DIR} not found.")
        return

    logger.info(f"### STARTING DATA NORMALISATION (Source Filter: {source_filter or 'ALL'}) ###")
    all_files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith(".json")]
    
    if source_filter:
        # Match variations of the source name
        source_filter = source_filter.lower()
        files = [f for f in all_files if source_filter in f.lower()]
        if not files:
            logger.warning(f"No file found for source: {source_filter}")
            return
    else:
        files = all_files

    manifest = {
        "run_timestamp": datetime.now().strftime("%Y_%m_%d_%H%M%S"),
        "type": "standardization",
        "processed_files": [],
        "total_records_processed": 0,
        "total_new_records": 0
    }

    for filename in files:
        file_path = os.path.join(ENRICHMENT_DIR, filename)
        source_name = filename.replace("_normalized.json", "").replace("_enriched.json", "").replace("_extracted.json", "").lower()
        
        source_tracking = load_source_tracking(source_name)
        latest_indicator_date_str = source_tracking.get("latest_indicator_date", "1970-01-01 00:00:00")
        
        try:
            # Parse tracking date for comparison
            try:
                # Make it UTC aware
                latest_indicator_date = datetime.fromisoformat(latest_indicator_date_str.replace(' ', 'T')).replace(tzinfo=timezone.utc)
            except:
                latest_indicator_date = datetime(1970, 1, 1, tzinfo=timezone.utc)

            with open(file_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            new_records = []
            logger.info(f"Processing {filename} ({len(records)} records)...")
            
            current_latest_date = latest_indicator_date
            
            for record in records:
                # Use collected_at for date-based tracking
                ts_str = record.get("collected_at", "")
                if not ts_str:
                    continue
                
                try:
                    # Handle both Z and +00:00 formats
                    record_date = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if record_date.tzinfo is None:
                        record_date = record_date.replace(tzinfo=timezone.utc)
                except:
                    continue

                if record_date <= latest_indicator_date:
                    continue
                
                # Normalize record
                record["standardized_at"] = datetime.now().isoformat()
                
                # Ensure ioc_enrichment exists for all IOCs
                for ioc in record.get("iocs", []):
                    if "ioc_enrichment" not in ioc:
                        ioc["ioc_enrichment"] = {}
                
                # Cleanup tags
                if "tags" in record and isinstance(record["tags"], list):
                    record["tags"] = sorted(list(set(filter(None, record["tags"]))))
                
                new_records.append(record)
                
                if record_date > current_latest_date:
                    current_latest_date = record_date

            if new_records:
                # Update tracking
                source_tracking["latest_indicator_date"] = current_latest_date.strftime("%Y-%m-%d %H:%M:%S")
                source_tracking["last_run"] = datetime.now().isoformat()
                source_tracking["last_sync_success"] = datetime.now().isoformat()
                save_source_tracking(source_name, source_tracking)
                
                # Save normalized data
                src_folder = os.path.join(NORM_OUTPUT_DIR, source_name)
                if not os.path.exists(src_folder): os.makedirs(src_folder)
                
                output_filename = f"{source_name}_normalized.json"
                output_path = os.path.join(src_folder, output_filename)
                
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(new_records, f, indent=2)
                
                manifest["processed_files"].append({
                    "source": source_name,
                    "new_records": len(new_records),
                    "output": output_filename
                })
                manifest["total_new_records"] += len(new_records)
                logger.info(f"  [OK] {len(new_records)} new records normalized for {source_name}")
            else:
                logger.info(f"  [SKIP] No new records for {source_name}")

            manifest["total_records_processed"] += len(records)

        except Exception as e:
            logger.error(f"Failed to process {filename}: {e}")

    # Save Run Manifest
    if manifest["processed_files"]:
        manifest_path = os.path.join(NORM_OUTPUT_DIR, f"manifest_{manifest['run_timestamp']}.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)
        logger.info(f"### NORMALISATION COMPLETED: {NORM_OUTPUT_DIR} ###")
    else:
        logger.info("### NORMALISATION COMPLETED: No new data to normalize ###")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standardize enriched JSON data")
    parser.add_argument("-s", "--source", help="Only standardize a specific source")
    args = parser.parse_args()
    standardize(source_filter=args.source)
