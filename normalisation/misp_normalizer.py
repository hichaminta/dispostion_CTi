import os
import json
import logging
import argparse
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MISPNormalizer")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
MISP_OUTPUT_DIR = os.path.join(BASE_DIR, "output_misp")

if not os.path.exists(MISP_OUTPUT_DIR):
    os.makedirs(MISP_OUTPUT_DIR)

TRACKING_DIR = os.path.join(BASE_DIR, "normalisation", "tracking_misp")
if not os.path.exists(TRACKING_DIR):
    os.makedirs(TRACKING_DIR)

def load_source_tracking(source):
    path = os.path.join(TRACKING_DIR, f"{source}_misp_tracking.json")
    default_tracking = {
        "latest_indicator_date": "1970-01-01 00:00:00",
        "last_run": None,
        "last_sync_success": None
    }
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key in default_tracking:
                    if key not in data:
                        data[key] = default_tracking[key]
                return data
        except Exception as e:
            logger.error(f"Error loading MISP tracking for {source}: {e}")
            return default_tracking
    return default_tracking

def save_source_tracking(source, data):
    path = os.path.join(TRACKING_DIR, f"{source}_misp_tracking.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving MISP tracking for {source}: {e}")

# Mapping internal types to MISP types
TYPE_MAPPING = {
    "ip": "ip-dst",
    "domaine": "domain",
    "url": "url",
    "hashe": "hash", # Will be refined by length
    "sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "email": "email-src"
}

def get_misp_type(internal_type, value):
    if internal_type == "hashe":
        vlen = len(value)
        if vlen == 32: return "md5"
        if vlen == 40: return "sha1"
        if vlen == 64: return "sha256"
        return "hash"
    return TYPE_MAPPING.get(internal_type, "other")

def normalize_to_misp(source_filter=None):
    """
    Groups data by source and date, then formats for MISP.
    """
    # Priority 1: output_enrichment (to take ALL enrichment information as requested)
    ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")
    if os.path.exists(ENRICHMENT_DIR) and any(f.endswith(".json") for f in os.listdir(ENRICHMENT_DIR)):
        current_output_dir = ENRICHMENT_DIR
        logger.info(f"Using enrichment data as primary input: {current_output_dir}")
    else:
        # Fallback to output_normaliser
        base_norm_dir = os.path.join(BASE_DIR, "output_normaliser")
        current_output_dir = base_norm_dir
        if os.path.exists(base_norm_dir):
            runs = [d for d in os.listdir(base_norm_dir) if d.startswith("run_") and os.path.isdir(os.path.join(base_norm_dir, d))]
            if runs:
                latest_run = sorted(runs)[-1]
                current_output_dir = os.path.join(base_norm_dir, latest_run)
                logger.info(f"Falling back to latest normalization run: {latest_run}")

    if not os.path.exists(current_output_dir) or not any(f.endswith(".json") for f in os.listdir(current_output_dir)):
        logger.warning(f"No files in {current_output_dir}. Falling back to output_cve_ioc.")
        current_output_dir = os.path.join(BASE_DIR, "output_cve_ioc")

    if not os.path.exists(current_output_dir):
        logger.error(f"Output directory {current_output_dir} not found.")
        return

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logger.info(f"### STARTING MISP NORMALISATION (Run: {run_ts}) ###")
    
    all_files = [f for f in os.listdir(current_output_dir) if f.endswith(".json")]
    
    if source_filter:
        target_norm = f"{source_filter.lower()}_normalized.json"
        target_enriched = f"{source_filter.lower()}_enriched.json"
        target_extracted = f"{source_filter.lower()}_extracted.json"
        files = [f for f in all_files if f in [target_norm, target_enriched, target_extracted]]
        if not files:
            logger.warning(f"No file found for source: {source_filter}")
            return
    else:
        files = all_files

    manifest = {
        "run_timestamp": run_ts,
        "source_filter": source_filter,
        "generated_files": [],
        "total_events": 0,
        "total_attributes": 0
    }

    for filename in files:
        file_path = os.path.join(current_output_dir, filename)
        source_name = filename.replace("_normalized.json", "").replace("_enriched.json", "").replace("_extracted.json", "").capitalize()
        
        logger.info(f"--- Processing Source: {source_name} ---")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            # Dictionnaire pour grouper par source : { "Source": { "Event": { ... } } }
            grouped_source_events = {}
            
            source_tracking = load_source_tracking(source_name.lower())
            latest_indicator_date_str = source_tracking.get("latest_indicator_date", "1970-01-01 00:00:00")
            
            try:
                latest_indicator_date = datetime.fromisoformat(latest_indicator_date_str.replace(' ', 'T')).replace(tzinfo=timezone.utc)
            except:
                latest_indicator_date = datetime(1970, 1, 1, tzinfo=timezone.utc)

            current_latest_date = latest_indicator_date
            new_records_count = 0
            
            for record in records:
                ts_str = record.get("collected_at")
                if not ts_str:
                    continue
                
                try:
                    record_date = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if record_date.tzinfo is None:
                        record_date = record_date.replace(tzinfo=timezone.utc)
                except:
                    continue

                if record_date <= latest_indicator_date:
                    continue
                
                source = record.get("source", "Unknown").capitalize()
                
                try:
                    event_date = record_date.strftime("%Y-%m-%d")
                except:
                    event_date = datetime.now().strftime("%Y-%m-%d")
                
                # Composite key: Source + Date to ensure division by date
                group_key = f"{source}|{event_date}"

                if group_key not in grouped_source_events:
                    grouped_source_events[group_key] = {
                        "Event": {
                            "info": f"CTI Source: {source} - {event_date}",
                            "date": event_date,
                            "timestamp": ts_str if ts_str else f"{event_date}T00:00:00Z",
                            "threat_level_id": "2",
                            "analysis": "0",
                            "distribution": "0",
                            "Attribute": [],
                            "Tag": [{"name": f"source:{source.lower()}"}]
                        }
                    }

                iocs = record.get("iocs", [])
                for ioc in iocs:
                    ioc_type = ioc.get("type", "").replace("domaine", "domain")
                    ioc_value = ioc.get("value", "")
                    enrichment = ioc.get("ioc_enrichment", {})

                    # Calcul de la confiance
                    # Security scores from various sources
                    vt_score = enrichment.get("vt_score")
                    urlscan_score = enrichment.get("urlscan_score")
                    abusesh_score = enrichment.get("abusesh_score") # Potential field
                    confidence_num = enrichment.get("confidence") # Numeric confidence (e.g. AbuseIPDB)
                    
                    # Force high confidence if any security score exists and is significant
                    has_security_score = (
                        (isinstance(vt_score, (int, float)) and vt_score > 0) or
                        (isinstance(urlscan_score, (int, float)) and urlscan_score > 0) or
                        (isinstance(abusesh_score, (int, float)) and abusesh_score > 0) or
                        (isinstance(confidence_num, (int, float)) and confidence_num >= 50) or
                        (isinstance(enrichment.get("vt_malicious_count"), (int, float)) and enrichment["vt_malicious_count"] > 0) or
                        enrichment.get("risk_flag") == "high" or
                        enrichment.get("is_compromised") == True or
                        enrichment.get("is_malicious") == True
                    )

                    relevant_fields = [
                        "asn", "country", "malware_family", "status", "hostname", 
                        "vt_score", "threat_type", "is_compromised", "risk_flag",
                        "server", "page_title"
                    ]
                    richness = sum(1 for field in relevant_fields if enrichment.get(field))
                    
                    if richness >= 5 or has_security_score: 
                        conf_level = "high"
                    elif richness >= 2: 
                        conf_level = "medium"
                    else: 
                        conf_level = "low"

                    m_type = get_misp_type(ioc_type, ioc_value)

                    main_attr = {
                        "type": m_type,
                        "value": ioc_value,
                        "to_ids": True,
                        "comment": "",
                        "Tag": [{"name": f"confidence:{conf_level}"}]
                    }

                    # Add enrichment to tags
                    if enrichment.get("malware_family"):
                        main_attr["Tag"].append({"name": f"malware:{enrichment['malware_family'].lower()}"})
                    
                    if enrichment.get("threat_type"):
                        main_attr["Tag"].append({"name": f"threat:{enrichment['threat_type'].lower()}"})
                    
                    if enrichment.get("risk_flag"):
                        main_attr["Tag"].append({"name": f"risk:{enrichment['risk_flag'].lower()}"})

                    if enrichment.get("is_compromised") or enrichment.get("is_malicious"):
                        main_attr["Tag"].append({"name": "status:compromised"})

                    if enrichment.get("country"):
                        main_attr["Tag"].append({"name": f"country:{enrichment['country'].upper()}"})
                    
                    if vt_score:
                        main_attr["Tag"].append({"name": f"virustotal:score={vt_score}"})
                    
                    if urlscan_score:
                        main_attr["Tag"].append({"name": f"urlscan:score={urlscan_score}"})

                    # Additional metadata in comment
                    meta_parts = []
                    if enrichment.get("record_id"): meta_parts.append(f"ID: {enrichment['record_id']}")
                    if enrichment.get("reporter"): meta_parts.append(f"Reporter: {enrichment['reporter']}")
                    if enrichment.get("asn"): meta_parts.append(f"ASN: {enrichment['asn']}")
                    if enrichment.get("country"): meta_parts.append(f"Country: {enrichment['country']}")
                    if enrichment.get("status"): meta_parts.append(f"Status: {enrichment['status']}")
                    if enrichment.get("server"): meta_parts.append(f"Server: {enrichment['server']}")
                    if enrichment.get("page_title"): meta_parts.append(f"Title: {enrichment['page_title']}")
                    if enrichment.get("urlscan_page_title"): meta_parts.append(f"PageTitle: {enrichment['urlscan_page_title']}")
                    
                    # VirusTotal Details
                    if vt_score is not None: meta_parts.append(f"VT: {vt_score}")
                    if enrichment.get("vt_malicious_count") is not None:
                        mal = enrichment["vt_malicious_count"]
                        tot = enrichment.get("vt_total_engines", "?")
                        meta_parts.append(f"VT_Detect: {mal}/{tot}")
                    if enrichment.get("vt_tags"):
                        meta_parts.append(f"VT_Tags: {', '.join(enrichment['vt_tags'])}")
                    
                    if urlscan_score is not None: meta_parts.append(f"URLScan Score: {urlscan_score}")
                    if confidence_num is not None: meta_parts.append(f"Conf: {confidence_num}%")
                    
                    # URLScan links and screenshots
                    if enrichment.get("urlscan_report_url"):
                        meta_parts.append(f"Report: {enrichment['urlscan_report_url']}")
                    if enrichment.get("urlscan_screenshot_url"):
                        meta_parts.append(f"Screenshot: {enrichment['urlscan_screenshot_url']}")
                    
                    # Flags
                    if enrichment.get("typosquat_flag"): meta_parts.append("Typosquat: Yes")
                    if enrichment.get("suspicious_keywords"): meta_parts.append(f"Keywords: {', '.join(enrichment['suspicious_keywords'])}")
                    
                    main_attr["comment"] = " | ".join(meta_parts) if meta_parts else f"Enriched from {source}"

                    grouped_source_events[group_key]["Event"]["Attribute"].append(main_attr)
                    
                    if record_date > current_latest_date:
                        current_latest_date = record_date
                    new_records_count += 1

            # Update tracking if new records were processed
            if new_records_count > 0:
                source_tracking["latest_indicator_date"] = current_latest_date.strftime("%Y-%m-%d %H:%M:%S")
                source_tracking["last_run"] = datetime.now().isoformat()
                source_tracking["last_sync_success"] = datetime.now().isoformat()
                save_source_tracking(source_name.lower(), source_tracking)

            # --- Sauvegarde des fichiers par source et date ---
            for group_key, event_wrapper in grouped_source_events.items():
                source_name, event_date = group_key.split("|")
                src_folder = os.path.join(MISP_OUTPUT_DIR, source_name.lower())
                if not os.path.exists(src_folder): os.makedirs(src_folder)

                output_filename = f"misp_{source_name.lower()}_{event_date}.json"
                output_path = os.path.join(src_folder, output_filename)
                
                manifest["generated_files"].append(f"{source_name.lower()}/{output_filename}")
                manifest["total_events"] += 1
                manifest["total_attributes"] += len(event_wrapper["Event"]["Attribute"])

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump([event_wrapper], f, indent=2)
                
                logger.info(f"  [OK] Generated MISP event for {source_name} ({event_date}) with {len(event_wrapper['Event']['Attribute'])} attributes")


        except Exception as e:
            logger.error(f"Failed to process {filename}: {e}")

    # Save tracking manifest
    manifest_path = os.path.join(MISP_OUTPUT_DIR, f"manifest_{manifest['run_timestamp']}.json")
    global_tracking_path = os.path.join(BASE_DIR, "normalisation", "tracking", f"misp_run_{manifest['run_timestamp']}.json")
    
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)
        
        # Also save to the global tracking folder
        with open(global_tracking_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)
            
        logger.info(f"### TRACKING MANIFEST CREATED: {manifest_path} ###")
        logger.info(f"### GLOBAL TRACKING UPDATED: {global_tracking_path} ###")
    except Exception as e:
        logger.error(f"Failed to save manifest: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize data for MISP export")
    parser.add_argument("-s", "--source", help="Source to normalize")
    args = parser.parse_args()
    
    normalize_to_misp(source_filter=args.source)
