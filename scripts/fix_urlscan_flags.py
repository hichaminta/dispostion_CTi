import os
import json
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("FixURLScanFlags")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

def fix_flags():
    if not os.path.exists(ENRICHMENT_DIR):
        logger.error(f"Enrichment directory not found: {ENRICHMENT_DIR}")
        return

    files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith("_enriched.json")]
    
    logger.info(f"Starting bulk update for {len(files)} files...")
    
    total_updated_records = 0
    total_updated_iocs = 0

    for filename in files:
        filepath = os.path.join(ENRICHMENT_DIR, filename)
        logger.info(f"Processing {filename} ({os.path.getsize(filepath) / (1024*1024):.2f} MB)...")
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            file_modified = False
            for record in data:
                record_modified = False
                for ioc in record.get("iocs", []):
                    if ioc.get("type") in ["url", "domain"]:
                        if "ioc_enrichment" not in ioc:
                            ioc["ioc_enrichment"] = {}
                        
                        modified_this_ioc = False
                        if ioc["ioc_enrichment"].get("passer_par_urlscan") != 1:
                            ioc["ioc_enrichment"]["passer_par_urlscan"] = 1
                            modified_this_ioc = True
                        
                        if ioc["ioc_enrichment"].get("canne_par_url") != 1:
                            ioc["ioc_enrichment"]["canne_par_url"] = 1
                            modified_this_ioc = True
                            
                        if modified_this_ioc:
                            record_modified = True
                            total_updated_iocs += 1
                
                if record_modified:
                    file_modified = True
                    total_updated_records += 1
            
            if file_modified:
                temp_filepath = filepath + ".tmp"
                with open(temp_filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                
                # Atomic swap
                os.replace(temp_filepath, filepath)
                logger.info(f"  [FIXED] {filename}")
            else:
                logger.info(f"  [OK] {filename} (no changes needed)")
                
        except Exception as e:
            logger.error(f"Failed to process {filename}: {e}")

    logger.info("### BULK UPDATE COMPLETED ###")
    logger.info(f"Total records modified: {total_updated_records}")
    logger.info(f"Total IOCs updated: {total_updated_iocs}")

if __name__ == "__main__":
    fix_flags()
