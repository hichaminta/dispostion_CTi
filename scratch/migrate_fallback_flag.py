import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger("Migration")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

OLD_FLAG = "passer_par_stage4_fallback"
NEW_FLAG = "passer_par_fallback"

def migrate_file(file_path):
    if not os.path.exists(file_path):
        return
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            if OLD_FLAG not in content:
                return
            
            data = json.loads(content)
        
        modified = False
        for record in data:
            for ioc in record.get("iocs", []):
                enr = ioc.get("ioc_enrichment", {})
                if OLD_FLAG in enr:
                    enr[NEW_FLAG] = enr.pop(OLD_FLAG)
                    modified = True
        
        if modified:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            logger.info(f"  [MIGRATED] {os.path.basename(file_path)}")
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON Error in {os.path.basename(file_path)}: {e}")
    except Exception as e:
        logger.error(f"Error migrating {os.path.basename(file_path)}: {e}")

def main():
    logger.info("### STARTING FLAG MIGRATION ###")
    if not os.path.exists(ENRICHMENT_DIR):
        logger.error("Enrichment directory not found.")
        return
        
    for f in os.listdir(ENRICHMENT_DIR):
        if f.endswith("_enriched.json"):
            migrate_file(os.path.join(ENRICHMENT_DIR, f))
            
    logger.info("### MIGRATION COMPLETED ###")

if __name__ == "__main__":
    main()
