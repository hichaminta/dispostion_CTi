import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import logging
import sys
import ipaddress

logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Sync_URLScan_Flags")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "__TEMP__/global_output/output_enrichment")
# FIX: Correct path to the registry file in the same directory
REGISTRY_FILE = os.path.join(os.path.dirname(__file__), "scanner_par_url_io.json")

FILES_TO_SYNC = [
    "abuseipdb_enriched.json",
    "alienvault_enriched.json", # Added AlienVault
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
        except Exception as e:
            logger.error(f"Failed to load registry: {e}")
            return {}
    return {}

def apply_urlscan_metadata(ioc, record, res):
    """Sync logic equivalent to enrichir_exclusive_urlscan.py"""
    modified = False
    
    if "ioc_enrichment" not in ioc: 
        ioc["ioc_enrichment"] = {}
        modified = True
    
    # Core flags
    if ioc["ioc_enrichment"].get("canne_par_url") != 1:
        ioc["ioc_enrichment"]["canne_par_url"] = 1
        modified = True
    if ioc["ioc_enrichment"].get("passer_par_urlscan") != 1:
        ioc["ioc_enrichment"]["passer_par_urlscan"] = 1
        modified = True
    
    # Metadata mapping (Attributes)
    if "attributes" not in record: 
        record["attributes"] = {}
        modified = True
        
    if "score" in res and record["attributes"].get("urlscan_score") != res["score"]:
        record["attributes"]["urlscan_score"] = res["score"]
        modified = True
    if "verdict" in res and record["attributes"].get("urlscan_verdict") != res["verdict"]:
        record["attributes"]["urlscan_verdict"] = res["verdict"]
        modified = True
    
    # Extra technical metadata to pass to ioc_enrichment
    for key in ["ip", "country", "server", "page_title", "effective_url", "screenshot_url", "report_url"]:
        if key in res and res[key]:
            attr_key = f"urlscan_{key}"
            if ioc["ioc_enrichment"].get(attr_key) != res[key]:
                ioc["ioc_enrichment"][attr_key] = res[key]
                modified = True
    
    return modified

def sync_flags():
    registry = load_registry()
    if not registry:
        logger.warning(f"Registry empty or not found at {REGISTRY_FILE}. Nothing to sync.")
        return

    logger.info(f"Loaded {len(registry)} entries from local URLScan database.")

    for filename in FILES_TO_SYNC:
        file_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(file_path):
            continue
        
        try:
            logger.info(f"Syncing {filename}...")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            modified_count = 0
            for record in data:
                record_modified = False
                if "iocs" in record:
                    for ioc in record["iocs"]:
                        ioc_type = ioc.get("type")
                        ioc_value = ioc.get("value")
                        if ioc_type not in ["url", "domain", "domaine", "ip"]: continue
                        
                        # Normalize IP/CIDR for registry lookup
                        lookup_value = ioc_value
                        if ioc_type == "ip":
                            try:
                                if '/' in ioc_value:
                                    lookup_value = str(ipaddress.ip_network(ioc_value, strict=False).network_address)
                            except: pass
                        
                        if lookup_value in registry:
                            if apply_urlscan_metadata(ioc, record, registry[lookup_value]):
                                record_modified = True
                
                if record_modified:
                    modified_count += 1
            
            if modified_count > 0:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"  [UPDATED] {modified_count} records in {filename}")
            else:
                logger.info(f"  [OK] No updates needed for {filename}")
                
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    logger.info("### STARTING POST-ENRICHMENT DATABASE SYNC ###")
    sync_flags()
    logger.info("### DATABASE SYNC COMPLETED ###")

