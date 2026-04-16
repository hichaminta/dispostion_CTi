import os
import json
import sys
import logging
import time
import requests
import argparse
from datetime import datetime

# Ensure we can import from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from enrichment.geolocalisation.geo_manager import GeoManager

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("geo_enrichment.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Enrichir")

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
TRACKING_DIR = os.path.join(BASE_DIR, "enrichment", "tracking")
GEO_BASE_FILE = os.path.join(os.path.dirname(__file__), "geo_base.json")

# API Configuration
EXTERNAL_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,country"

def get_tracking_file(source):
    return os.path.join(TRACKING_DIR, f"{source}_tracking.json")

def load_source_tracking(source):
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)
    path = get_tracking_file(source)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_source_tracking(source, data):
    path = get_tracking_file(source)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def fetch_external_geo(ip):
    """
    Fetches geolocation data from ip-api.com.
    Rate limited to avoid being blocked.
    """
    if not ip: return None, None
    # Normalize IP for API: remove port and CIDR mask
    clean_ip = ip.split(':')[0].split('/')[0].strip()
    
    try:
        url = EXTERNAL_API_URL.format(ip=clean_ip)
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return data.get("countryCode"), data.get("country")
            else:
                logger.warning(f"API returned {data.get('status')} for {clean_ip}: {data.get('message')}")
        elif response.status_code == 429:
            logger.warning("Rate limit reached for API. Sleeping...")
            time.sleep(60) # Wait a minute if rate limited
    except Exception as e:
        logger.error(f"Error calling API for {clean_ip}: {e}")
    return None, None

def get_source_from_filename(filename):
    """Extracts source name from filename (e.g., feodotracker_enriched.json -> feodotracker)"""
    return filename.replace("_enriched.json", "")

def enrich_all(source_filter=None):
    geo_mgr = GeoManager(GEO_BASE_FILE)
    
    if not os.path.exists(OUTPUT_DIR):
        logger.error(f"Enrichment directory not found: {OUTPUT_DIR}")
        return

    all_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")]
    
    if source_filter:
        files = [f for f in all_files if source_filter in f]
        if not files:
            logger.warning(f"No files found matching source filter: {source_filter}")
            return
        logger.info(f"### FILTERED RUN: Source '{source_filter}' ###")
    else:
        files = all_files
        logger.info("### STAGE 2: GLOBAL GEOLOCATION ENRICHMENT STARTED ###")

    logger.info(f"Analyzing {len(files)} sources for infrastructure mapping...")

    total_new_geos = 0
    api_call_count = 0

    for filename in files:
        source = get_source_from_filename(filename)
        file_path = os.path.join(OUTPUT_DIR, filename)
        
        # Load source tracking (Unified with NLP)
        source_data = load_source_tracking(source)
        
        # Ensure 'geo' section and all keys exist (Robust Initialization)
        if "geo" not in source_data or not isinstance(source_data["geo"], dict):
            source_data["geo"] = {}
        
        geo_defaults = {
            "first_ip_date": None,
            "last_ip_date": None,
            "total_ips": 0,
            "last_run": None,
            "files_processed": []
        }
        for k, v in geo_defaults.items():
            if k not in source_data["geo"]:
                source_data["geo"][k] = v

        last_ip_date_str = source_data["geo"].get("last_ip_date")
        last_ip_date = None
        if last_ip_date_str:
            try:
                last_ip_date = datetime.fromisoformat(last_ip_date_str.replace('Z', '+00:00'))
            except: pass
        
        logger.info(f"Processing source: {source} (File: {filename})")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            modified = False
            file_min_date = None
            file_max_date = None
            
            # --- PHASE 1: COLLECT UNIQUE IPs ---
            unique_raw_ips = set()
            for record in data:
                # Quick date check to skip already processed records (Efficiency)
                record_ts_str = record.get("collected_at") or record.get("extracted_at") or record.get("first_seen")
                if record_ts_str and last_ip_date:
                    try:
                        record_ts = datetime.fromisoformat(record_ts_str.replace('Z', '+00:00'))
                        if record_ts <= last_ip_date:
                            continue
                    except: pass
                
                for ioc in record.get("iocs", []):
                    if ioc.get("type") == "ip":
                        val = ioc.get("value")
                        if val: unique_raw_ips.add(val)

            # --- PHASE 2: BATCH LOOKUP AND CACHE POPULATION ---
            # This ensures we call the API only ONCE per unique IP value found in the file
            lookup_cache = {} # raw_ip -> (code, name)
            
            if unique_raw_ips:
                logger.info(f"Found {len(unique_raw_ips)} unique IPs to verify for {source}")
                
            for raw_ip in sorted(list(unique_raw_ips)):
                # 1. Normalize and check local DB cache
                clean_ip = raw_ip.split(':')[0].split('/')[0].strip()
                country_code = geo_mgr.get_country(clean_ip)
                country_name = None
                
                if not country_code:
                    # 2. API Lookup (once per run)
                    logger.info(f"IP {raw_ip} (Clean: {clean_ip}) not in cache. Calling API...")
                    # Rate limit: max 45 requests per minute -> ~1.5s delay
                    time.sleep(1.5)
                    country_code, country_name = fetch_external_geo(clean_ip)
                    api_call_count += 1
                    
                    if country_code:
                        logger.info(f"API result for {clean_ip}: {country_code}. Saving to cache.")
                        geo_mgr.insert_mapping(clean_ip, country_code, country_name, source="ip-api.com", auto_save=True)
                        total_new_geos += 1
                    else:
                        # Optional: Negative Cache entry (save as UNKNOWN to avoid retries in this run)
                        # geo_mgr.insert_mapping(clean_ip, "??", None, source="ip-api.com_failed", auto_save=True)
                        pass

                if country_code:
                    lookup_cache[raw_ip] = (country_code, country_name)

            # --- PHASE 3: APPLY ENRICHMENT ---
            for record in data:
                record_ts_str = record.get("collected_at") or record.get("extracted_at") or record.get("first_seen")
                if record_ts_str:
                    try:
                        if not file_min_date or record_ts_str < file_min_date: file_min_date = record_ts_str
                        if not file_max_date or record_ts_str > file_max_date: file_max_date = record_ts_str
                        
                        # Skip if record is in the past
                        if last_ip_date:
                            record_ts = datetime.fromisoformat(record_ts_str.replace('Z', '+00:00'))
                            if record_ts <= last_ip_date:
                                continue
                    except: pass

                record_modified = False
                for ioc in record.get("iocs", []):
                    if ioc.get("type") == "ip":
                        raw_ip = ioc.get("value")
                        if raw_ip in lookup_cache:
                            country_code, country_name = lookup_cache[raw_ip]
                            
                            # Update Per-IOC metadata
                            if "ioc_enrichment" not in ioc: ioc["ioc_enrichment"] = {}
                            if ioc["ioc_enrichment"].get("country") != country_code:
                                ioc["ioc_enrichment"]["country"] = country_code
                                record_modified = True

                            if country_name and ioc["ioc_enrichment"].get("country_name") != country_name:
                                ioc["ioc_enrichment"]["country_name"] = country_name
                                record_modified = True

                            # Update Record-level Metadata
                            if "enrichment" not in record: record["enrichment"] = {}
                            if "nlp_advanced" not in record["enrichment"]: record["enrichment"]["nlp_advanced"] = {}
                            
                            geo_list = record["enrichment"]["nlp_advanced"].get("geography", [])
                            if country_code not in geo_list:
                                geo_list.append(country_code)
                                record["enrichment"]["nlp_advanced"]["geography"] = sorted(geo_list)
                                record_modified = True
                            
                            tags = record.get("tags", [])
                            if country_code.lower() not in [t.lower() for t in tags]:
                                tags.append(country_code)
                                record["tags"] = sorted(list(set(tags)))
                                record_modified = True
                
                if record_modified:
                    modified = True
            
            # --- After Loop ---
            geo_stats = source_data["geo"]
            if file_min_date:
                existing_min = geo_stats.get("first_ip_date")
                if not existing_min or file_min_date < existing_min:
                    geo_stats["first_ip_date"] = file_min_date
            if file_max_date:
                if not geo_stats.get("last_ip_date") or file_max_date > geo_stats["last_ip_date"]:
                    geo_stats["last_ip_date"] = file_max_date
            
            geo_stats["total_ips"] = len(data)
            geo_stats["last_run"] = datetime.now().isoformat()
            if filename not in geo_stats.get("files_processed", []):
                if "files_processed" not in geo_stats: geo_stats["files_processed"] = []
                geo_stats["files_processed"].append(filename)
                
            save_source_tracking(source, source_data)
            
            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"Updated {filename} with new geolocation data.")
            else:
                logger.info(f"No changes for {filename}")

        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

    logger.info("### GEOLOCATION ENRICHMENT COMPLETED ###")
    logger.info(f"Summary: {total_new_geos} new IPs identified and cached. Total API calls: {api_call_count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Geolocation Enrichment Engine")
    parser.add_argument("-s", "--source", help="Only enrich a specific source (e.g. feodotracker)")
    args = parser.parse_args()
    
    enrich_all(source_filter=args.source)
