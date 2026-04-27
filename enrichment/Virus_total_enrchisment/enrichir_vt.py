import os
import json
import sys
import logging
import time
from datetime import datetime

# Ensure we can import from current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from vt_client import VTClient

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("VT_Enrichment")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
REGISTRY_FILE = os.path.join(os.path.dirname(__file__), "vt_registry.json")

# Throttling for Public API (4 requests/min = 15s delay)
THROTTLE_DELAY = 16 

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except: return {}
    return {}

def save_registry(registry):
    try:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to save registry: {e}")

def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def apply_vt_metadata(ioc, record, res):
    """Applies VirusTotal metadata to an IOC and its parent record."""
    if "ioc_enrichment" not in ioc: ioc["ioc_enrichment"] = {}
    
    # Mark as scanned by VirusTotal
    ioc["ioc_enrichment"]["passer_par_virustotal"] = 1
    
    if res == "NOT_FOUND":
        ioc["ioc_enrichment"]["vt_status"] = "NOT_FOUND"
        return True

    attr = res.get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    
    # Enrich IOC object
    ioc["ioc_enrichment"]["vt_reputation"] = attr.get("reputation", 0)
    ioc["ioc_enrichment"]["vt_malicious_count"] = stats.get("malicious", 0)
    ioc["ioc_enrichment"]["vt_total_engines"] = sum(stats.values()) if stats else 0
    ioc["ioc_enrichment"]["vt_tags"] = attr.get("tags", [])
    
    last_date = attr.get("last_analysis_date")
    if last_date:
        ioc["ioc_enrichment"]["vt_last_analysis"] = datetime.fromtimestamp(last_date).isoformat()

    # Enrich parent Record attributes (aggregated)
    if "attributes" not in record: record["attributes"] = {}
    
    # Update record reputation if VT score is significant
    if ioc["ioc_enrichment"]["vt_malicious_count"] > 0:
        record["attributes"]["vt_score"] = ioc["ioc_enrichment"]["vt_malicious_count"]
        record["attributes"]["is_malicious"] = True
        
    return True

def enrich_with_virustotal():
    client = VTClient()
    registry = load_registry()
    
    if not os.path.exists(OUTPUT_DIR):
        logger.error(f"Output directory not found: {OUTPUT_DIR}")
        return

    files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")]
    logger.info(f"### VIRUSTOTAL ENRICHMENT STARTED (Prioritized: Hashes > Domains/URLs > IPs) ###")

    limit_reached = False
    new_scans = 0
    cache_hits = 0

    # Load all files into memory to allow prioritization across files
    all_file_data = {}
    for filename in files:
        # Ignore AlienVault/OTX files as requested
        if "alienvault" in filename.lower() or "otx" in filename.lower():
            logger.info(f"--- [IGNORE] Skipping AlienVault/OTX source file: {filename} ---")
            continue
            
        file_path = os.path.join(OUTPUT_DIR, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                all_file_data[filename] = json.load(f)
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")

    # PRIORITY PASSES
    # [TEMPORARY] Only enriching Hashes as requested
    priority_groups = [
        ["hash", "md5", "sha1", "sha256", "hashe"], # Priority 1 (Only one active for now)
    ]

    for type_group in priority_groups:
        if limit_reached: break
        
        logger.info(f"--- Processing Priority Group: {type_group} ---")
        
        for filename, data in all_file_data.items():
            if limit_reached: break
            
            modified = False
            for record in data:
                if limit_reached: break
                
                for ioc in record.get("iocs", []):
                    ioc_type = ioc.get("type", "").lower()
                    ioc_value = ioc.get("value")
                    
                    if not ioc_value or ioc_type not in type_group:
                        continue
                    
                    # Skip if already marked as scanned by VT
                    if ioc.get("ioc_enrichment", {}).get("passer_par_virustotal") == 1:
                        continue

                    # Check Registry (Cache) - Cache hits don't count towards API limit
                    if ioc_value in registry:
                        if apply_vt_metadata(ioc, record, registry[ioc_value]):
                            cache_hits += 1
                            modified = True
                        continue

                    # API Call
                    logger.info(f"  [API] Scanning {ioc_type}: {ioc_value[:30]}...")
                    
                    res = None
                    if ioc_type in ["ip", "ip_address"]:
                        res = client.get_ip_report(ioc_value)
                    elif ioc_type in ["domain", "domaine"]:
                        res = client.get_domain_report(ioc_value)
                    elif ioc_type == "url":
                        res = client.get_url_report(ioc_value)
                    elif ioc_type in ["hash", "md5", "sha1", "sha256", "hashe"]:
                        res = client.get_file_report(ioc_value)
                    
                    if res == "LIMIT_REACHED":
                        limit_reached = True
                        logger.warning("!!! VirusTotal API Quota Reached !!!")
                        break
                    
                    if res:
                        registry[ioc_value] = res
                        if apply_vt_metadata(ioc, record, res):
                            modified = True
                            new_scans += 1
                        
                        save_registry(registry)
                        time.sleep(THROTTLE_DELAY)

            if modified:
                file_path = os.path.join(OUTPUT_DIR, filename)
                save_json_file(file_path, data)
                logger.info(f"  [SAVED] Updated {filename} (after priority pass)")

    logger.info(f"VT Enrichment Completed. New Scans: {new_scans}, Cache Hits: {cache_hits}")

    logger.info(f"VT Enrichment Completed. New Scans: {new_scans}, Cache Hits: {cache_hits}")

if __name__ == "__main__":
    enrich_with_virustotal()
