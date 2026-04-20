import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Sync_URLScan_Flags")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
REGISTRY_FILE = os.path.join(BASE_DIR, "enrichment", "urlscan_enrichment", "scanner_par_url_io.json")

FILES_TO_SYNC = [
    "abuseipdb_enriched.json",
    "cins_army_enriched.json",
    "feodotracker_enriched.json",
    "malwarebazaar_enriched.json",
    "openphish_enriched.json",
    "phishtank_enriched.json",
    "pulsedive_enriched.json",
    "spamhaus_enriched.json",
    "threatfox_enriched.json",
    "urlhaus_enriched.json",
    "virustotal_enriched.json"
]

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except: return {}
    return {}

def sync_flags():
    registry = load_registry()
    if not registry:
        logger.warning("Registry empty or not found. Nothing to sync.")
        return

    for filename in FILES_TO_SYNC:
        file_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            continue
        
        try:
            logger.info(f"Syncing flags in {filename}...")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            modified_count = 0
            for record in data:
                record_modified = False
                if "iocs" in record:
                    if "attributes" not in record: record["attributes"] = {}
                    
                    for ioc in record["iocs"]:
                        ioc_type = ioc.get("type")
                        ioc_value = ioc.get("value")
                        if ioc_type not in ["url", "domain"]: continue
                        
                        if ioc_value in registry:
                            res = registry[ioc_value]
                            if "ioc_enrichment" not in ioc: ioc["ioc_enrichment"] = {}
                            
                            # Core Flags
                            if ioc["ioc_enrichment"].get("canne_par_url") != 1:
                                ioc["ioc_enrichment"]["canne_par_url"] = 1
                                ioc["ioc_enrichment"]["passer_par_urlscan"] = 1
                                record_modified = True
                            
                            # Sync metadata if available
                            if "score" in res and record["attributes"].get("urlscan_score") != res["score"]:
                                record["attributes"]["urlscan_score"] = res["score"]
                                record_modified = True
                            if "verdict" in res and record["attributes"].get("urlscan_verdict") != res["verdict"]:
                                record["attributes"]["urlscan_verdict"] = res["verdict"]
                                record_modified = True
                            
                            # Sync extra tech details
                            for key in ["ip", "country", "server", "page_title", "effective_url", "screenshot_url", "report_url"]:
                                if key in res and res[key]:
                                    attr_key = f"urlscan_{key}"
                                    if ioc["ioc_enrichment"].get(attr_key) != res[key]:
                                        ioc["ioc_enrichment"][attr_key] = res[key]
                                        record_modified = True
                
                if record_modified:
                    modified_count += 1
            
            if modified_count > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"Updated {modified_count} records in {filename}")
            else:
                logger.info(f"No changes needed for {filename}")
                
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    logger.info("### URLScan Flag Synchronization Started ###")
    sync_flags()
    logger.info("### URLScan Flag Synchronization Finished ###")
