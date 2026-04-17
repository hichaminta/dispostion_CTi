import os
import json
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Standardizer")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

def standardize(source_filter=None):
    """
    Standardizes the JSON structure of all enriched files.
    - Ensures consistent fields.
    - Cleans up any leftover nulls.
    - Adds a 'standardized_at' timestamp.
    """
    if not os.path.exists(ENRICHMENT_DIR):
        logger.error(f"Enrichment directory {ENRICHMENT_DIR} not found.")
        return

    logger.info("### STARTING DATA NORMALISATION ###")
    
    all_files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith("_enriched.json")]
    
    if source_filter:
        target = f"{source_filter.lower()}_enriched.json"
        files = [f for f in all_files if f == target]
        if not files:
            logger.warning(f"No enriched file found for source: {source_filter}")
            return
        logger.info(f"Filtered normalisation for source: {source_filter}")
    else:
        files = all_files

    for filename in files:
        file_path = os.path.join(ENRICHMENT_DIR, filename)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            modified = False
            for record in records:
                # Top level metadata
                if "standardized_at" not in record:
                    record["standardized_at"] = datetime.now().isoformat()
                    modified = True
                
                # Normalize IOCs
                for ioc in record.get("iocs", []):
                    if "ioc_enrichment" not in ioc:
                        ioc["ioc_enrichment"] = {}
                        modified = True
                    
                    # Ensure geo structure
                    if "geography" not in ioc["ioc_enrichment"]:
                        ioc["ioc_enrichment"]["geography"] = []
                        modified = True
                
                # Normalize tags (remove duplicates)
                if "tags" in record and isinstance(record["tags"], list):
                    prev_len = len(record["tags"])
                    record["tags"] = sorted(list(set(record["tags"])))
                    if len(record["tags"]) != prev_len: modified = True

            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=4)
                logger.info(f"  [OK] Standardized {filename}")
            else:
                logger.info(f"  [SKIP] {filename} already standardized")

        except Exception as e:
            logger.error(f"Failed to standardize {filename}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standardize enriched JSON data (Optional: for a specific source)")
    parser.add_argument("-s", "--source", help="Only standardize the file for this specific source")
    args = parser.parse_args()
    
    standardize(source_filter=args.source)
