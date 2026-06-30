import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import sys
import logging
import argparse
import time
import re
import asyncio
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

# --- Windows Asyncio Fix ---
if sys.platform == 'win32':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except: pass
# ---------------------------

# Ensure we can import from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from enrichment.enrichment_url.urlscan_client import URLScanClient

# Setup logging
logging.basicConfig(encoding="utf-8", 
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("URLScan_Exclusive")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "__TEMP__/global_output/output_enrichment")
TRACKING_DIR = os.path.join(BASE_DIR, "tracking", "tracking_enrichment")
WHITELIST_FILE = os.path.join(BASE_DIR, "hwite.json")

INVALID_EXTENSIONS = [
    '.dll', '.exe', '.png', '.jpg', '.jpeg', '.gif', '.msi', '.bat', 
    '.vbs', '.scr', '.js', '.hta', '.tmp', '.bin', '.dat', '.file', 
    '.arm', '.mpsl', '.mips', '.variant', '.ulise', '.elf', '.sh',
    '.zip', '.tar', '.rar', '.7z', '.jar', '.iso', '.lnk', '.gz'
]

def is_valid_urlscan_target(value, ioc_type="url"):
    """
    Heuristic to skip non-valid web targets (malware names, file names).
    """
    if not value or not isinstance(value, str): return False
    
    # If it's an IP, validate it
    if ioc_type == "ip":
        return value

    val_low = value.lower()
    
    # Skip if it ends with a blacklisted extension
    if any(val_low.endswith(ext) for ext in INVALID_EXTENSIONS):
        return False
        
    # Skip malware family names often extracted as domains
    if val_low.startswith('trojan.') or val_low.startswith('malware.'):
        return False
        
    # Minimum requirement: must contain at least one dot and be at least 5 chars
    if '.' not in value or len(value) < 5:
        return False
        
    return value


class WhitelistChecker:
    def __init__(self, path):
        self.path = path
        self.whitelist = {"domains": [], "urls": []}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.whitelist = json.load(f)
            except: pass

    def is_safe(self, value):
        try:
            if value in self.whitelist.get("urls", []): return True
            hostname = value
            if "://" in value: hostname = urlparse(value).hostname or ""
            hostname = hostname.lower()
            for domain in self.whitelist.get("domains", []):
                domain = domain.lower()
                if hostname == domain or hostname.endswith("." + domain): return True
        except: pass
        return False
    
    def add(self, value, is_url=False):
        """Adds a value to the local whitelist and saves to disk."""
        key = "urls" if is_url else "domains"
        if value not in self.whitelist[key]:
            self.whitelist[key].append(value)
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.whitelist, f, indent=4)
                logger.info(f"  [WHITELIST] Added {value} to {key}")
            except Exception as e:
                logger.error(f"Failed to update whitelist: {e}")

def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def get_source_from_filename(filename):
    return filename.replace("_enriched.json", "")

def enrich_urlscan(source_filter=None):
    """
    100% URLScan Module: Purges old heuristics and adds rich metadata.
    Includes standardized tracking compatible with NLP and GEO stages.
    """
    urlscan = URLScanClient()
    checker = WhitelistChecker(WHITELIST_FILE)
    
    if not os.path.exists(OUTPUT_DIR): return

    all_files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")])
    
    # Special Fix: 'Pipeline Complet' means process all files
    if source_filter and source_filter.lower() == "unified extraction":
        files = all_files
    else:
        files = [f for f in all_files if source_filter.lower() in f.lower()] if source_filter else all_files

    logger.info(f"### RICH DYNAMIC ENRICHMENT (URLScan.io) STARTED ###")

    new_submissions = 0
    results_fetched = 0
    dns_errors = 0
    limit_reached = False
    start_time = time.time()
    MAX_RUNTIME = 3600 # 1 hour
    MAX_SUBMISSIONS_PER_SOURCE = 50 

    REGISTRY_FILE = os.path.join(os.path.dirname(__file__), "scanner_par_url_io.json")
    
    # --- Registry Management ---
    def load_registry():
        if os.path.exists(REGISTRY_FILE):
            try:
                with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except: 
                logger.error("Failed to load registry file!")
                return {}
        return {}

    def save_registry(registry):
        try:
            with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
                json.dump(registry, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")

    registry = load_registry()
    
    def get_from_registry(value):
        """Attempts to find an IOC in the registry with normalization."""
        # 1. Exact match
        if value in registry: return registry[value]
        
        # 2. Try with/without protocol
        if "://" in value:
            # Extract domain
            domain = urlparse(value).hostname
            if domain and domain in registry: return registry[domain]
        else:
            # Try common protocols
            for proto in ["http://", "https://"]:
                alt = f"{proto}{value}"
                if alt in registry: return registry[alt]
        
        return None

    def apply_urlscan_metadata(ioc, record, res):
        """Helper to apply full URLScan metadata from a result object (registry or API)"""
        # Ensure ioc_enrichment structure
        if "ioc_enrichment" not in ioc: ioc["ioc_enrichment"] = {}
        
        # Purge old metadata
        for k in ["url_analysis", "domain_analysis", "url_scan"]:
            if k in ioc["ioc_enrichment"]: del ioc["ioc_enrichment"][k]
        
        # Core flags
        ioc["ioc_enrichment"]["canne_par_url"] = 1
        # Explicit marker that this indicator was processed by URLScan (even if from local cache)
        ioc["ioc_enrichment"]["passer_par_urlscan"] = 1
        
        now_iso = datetime.now().isoformat()
        ioc["ioc_enrichment"]["tlp"] = "TLP:CLEAR"
        ioc["ioc_enrichment"]["enriched_at"] = now_iso
        
        # Handle special "DOWN" or "DNS_ERROR" status
        if res.get("status") == "DNS_ERROR":
            ioc["ioc_enrichment"]["urlscan_status"] = "DOWN"
            record["attributes"]["urlscan_verdict"] = "DNS_ERROR"
            return True

        # Metadata mapping
        if "score" in res: 
            record["attributes"]["urlscan_score"] = res["score"]
            record["attributes"]["tlp"] = "TLP:CLEAR"
            record["attributes"]["enriched_at"] = now_iso
        
        if "verdict" in res: record["attributes"]["urlscan_verdict"] = res["verdict"]
        
        # Extra technical metadata to pass to ioc_enrichment
        for key in ["country", "server", "ip", "page_title", "effective_url", "screenshot_url", "report_url"]:
            if key in res and res[key]:
                ioc["ioc_enrichment"][f"urlscan_{key}"] = res[key]
        
        return True

    # ---------------------------

    for filename in files:
        # Exclude AlienVault/OTX files as requested
        if "otx_alienvault" in filename.lower() or "alienvault" in filename.lower():
            logger.info(f"--- [IGNORE] Skipping AlienVault/OTX source file: {filename} ---")
            continue

        if limit_reached: 
            logger.warning(f"--- [QUOTA REACHED] Skipping {filename} ---")
            continue

        source = get_source_from_filename(filename)
        file_path = os.path.join(OUTPUT_DIR, filename)
        
        logger.info(f">>> STARTING SOURCE: {source.upper()} <<<")
        source_submissions = 0
        
        # Standard mode: process all indicators in the file
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            modified = False
            records_to_keep = []

            for record in data:
                if (time.time() - start_time) > MAX_RUNTIME: 
                    records_to_keep.append(record)
                    continue

                record_modified = False
                # Technical metadata update: Ensure attributes exist
                if "attributes" not in record: record["attributes"] = {}

                for ioc in record.get("iocs", []):
                    ioc_type = ioc.get("type")
                    ioc_value = ioc.get("value")
                    if ioc_type not in ["url", "domain", "domaine", "ip"]: continue

                    # --- SKIP IF ALREADY MARKED (NEW LOGIC) ---
                    if ioc.get("ioc_enrichment", {}).get("passer_par_urlscan") == 1:
                        # Still try to sync metadata if missing high-level attributes
                        if not record.get("attributes", {}).get("urlscan_score") and ioc_value in registry:
                            if apply_urlscan_metadata(ioc, record, registry[ioc_value]):
                                logger.info(f"  [SYNC] {ioc_value[:30]}... Metadata synced from local URLScan registry")
                                record_modified = True
                        continue
                    # -----------------------------------------

                    # 1. DATABASE FIRST (PRIORITY)
                    db_entry = get_from_registry(ioc_value)
                    if db_entry:
                        if apply_urlscan_metadata(ioc, record, db_entry):
                            logger.info(f"  [DB MATCH] {ioc_value[:40]}... Data applied from local DB (via URLScan)")
                            record_modified = True
                            results_fetched += 1
                        continue

                    # 2. API CALL (ONLY IF NOT IN DB)
                    if not limit_reached:
                        if source_submissions >= MAX_SUBMISSIONS_PER_SOURCE: continue
                        
                        # Normalize and validate
                        target_value = is_valid_urlscan_target(ioc_value, ioc_type)
                        if not target_value: continue
                        
                        if checker.is_safe(target_value): continue
                        
                        uuid = urlscan.submit_scan(target_value)
                        if uuid == "LIMIT_REACHED":
                            limit_reached = True
                            logger.warning("!!! [LIMIT] Quota API atteint !!!")
                            break
                        elif uuid == "DNS_ERROR":
                            # CACHE DNS ERROR TO AVOID RETRYING
                            dns_data = {
                                "status": "DNS_ERROR",
                                "last_scanned": datetime.now().isoformat()
                            }
                            registry[target_value] = dns_data
                            save_registry(registry)
                            
                            if apply_urlscan_metadata(ioc, record, dns_data):
                                record_modified = True
                            
                            dns_errors += 1
                            logger.warning(f"  [DNS_ERROR] {target_value[:30]}... Cached as DOWN")
                            continue
                        elif uuid:
                            logger.info(f"  [SUBMIT] {target_value[:30]}... Poll en cours (60s max)...")
                            # ACTIVE POLLING
                            attempts = 0
                            while attempts < 12:
                                time.sleep(5)
                                result = urlscan.fetch_result(uuid)
                                if result and result != "PENDING":
                                    # SUCCESS: Extract Rich Data
                                    page = result.get("page", {})
                                    verdicts = result.get("verdicts", {}).get("overall", {})
                                    
                                    rich_data = {
                                        "score": verdicts.get("score", 0),
                                        "verdict": verdicts.get("malicious", False),
                                        "page_title": page.get("title"),
                                        "effective_url": page.get("url"),
                                        "domain": page.get("domain"),
                                        "country": page.get("country"),
                                        "server": page.get("server"),
                                        "ip": page.get("ip"),
                                        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
                                        "report_url": f"https://urlscan.io/result/{uuid}/",
                                        "last_scanned": datetime.now().isoformat()
                                    }
                                    
                                    # Save to Registry
                                    registry[ioc_value] = rich_data
                                    save_registry(registry)
                                    
                                    # Apply to Record
                                    if apply_urlscan_metadata(ioc, record, rich_data):
                                        record_modified = True
                                    
                                    new_submissions += 1
                                    source_submissions += 1
                                    logger.info(f"  [DONE] {ioc_value[:30]} -> Score: {rich_data['score']}")
                                    break
                                attempts += 1
                            
                            if attempts >= 12:
                                logger.warning(f"  [TIMEOUT] Scan {uuid} toujours en attente après 60s.")

                if record_modified:
                    modified = True
                
                records_to_keep.append(record)
                if limit_reached: break

            if modified: 
                save_json_file(file_path, records_to_keep)
                logger.info(f"  [SAVED] Updated {filename}")

            logger.info(f">>> FINISHED {source.upper()}: Submits: {source_submissions} <<<")
            if limit_reached: break

        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

    logger.info(f"URLScan Enrichment Completed. Registry updated. DB Matches: {results_fetched}, API Submissions: {new_submissions}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone URLScan.io Enrichment Module")
    parser.add_argument("-s", "--source", help="Only process a specific source")
    args = parser.parse_args()
    enrich_urlscan(source_filter=args.source)
