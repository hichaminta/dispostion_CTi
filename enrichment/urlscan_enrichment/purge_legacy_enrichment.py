import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("LegacyPurge")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")

def purge_file(file_path):
    """Processes a single file to remove legacy enrichment data."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        modified = False
        purge_count = 0
        for record in data:
            for ioc in record.get("iocs", []):
                if "ioc_enrichment" in ioc:
                    # Remove URL Heuristics
                    if "url_analysis" in ioc["ioc_enrichment"]:
                        del ioc["ioc_enrichment"]["url_analysis"]
                        modified = True
                        purge_count += 1
                    
                    # Remove Domain Heuristics
                    if "domain_analysis" in ioc["ioc_enrichment"]:
                        del ioc["ioc_enrichment"]["domain_analysis"]
                        modified = True
                        purge_count += 1

        if modified:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            return True, purge_count
        return False, 0
    except Exception as e:
        logger.error(f"Error processing {os.path.basename(file_path)}: {e}")
        return False, 0

def main():
    if not os.path.exists(OUTPUT_DIR): return

    files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")]
    logger.info(f"### STARTING ROBUST PURGE (Files: {len(files)}) ###")

    for filename in files:
        file_path = os.path.join(OUTPUT_DIR, filename)
        logger.info(f"Processing {filename}...")
        success, count = purge_file(file_path)
        if success:
            logger.info(f"  [OK] Cleaned {count} blocks.")
        else:
            logger.info(f"  [SKIP] Already clean.")

if __name__ == "__main__":
    main()
