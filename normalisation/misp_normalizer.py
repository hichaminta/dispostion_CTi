import os
import json
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MISPNormalizer")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
MISP_OUTPUT_DIR = os.path.join(BASE_DIR, "output_misp")

if not os.path.exists(MISP_OUTPUT_DIR):
    os.makedirs(MISP_OUTPUT_DIR)

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
    base_norm_dir = os.path.join(BASE_DIR, "output_normaliser")
    current_output_dir = base_norm_dir
    
    # Check for run_ subfolders (latest run)
    if os.path.exists(base_norm_dir):
        runs = [d for d in os.listdir(base_norm_dir) if d.startswith("run_") and os.path.isdir(os.path.join(base_norm_dir, d))]
        if runs:
            latest_run = sorted(runs)[-1]
            current_output_dir = os.path.join(base_norm_dir, latest_run)
            logger.info(f"Using latest normalization run: {latest_run}")

    if not os.path.exists(current_output_dir) or not any(f.endswith(".json") for f in os.listdir(current_output_dir)):
        logger.warning(f"No files in {current_output_dir}. Falling back to output_enrichment.")
        current_output_dir = os.path.join(BASE_DIR, "output_enrichment")
        
        if not os.path.exists(current_output_dir) or not any(f.endswith(".json") for f in os.listdir(current_output_dir)):
            logger.warning(f"No files in {current_output_dir}. Falling back to output_cve_ioc.")
            current_output_dir = os.path.join(BASE_DIR, "output_cve_ioc")

    if not os.path.exists(current_output_dir):
        logger.error(f"Output directory {current_output_dir} not found.")
        return

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_folder = os.path.join(MISP_OUTPUT_DIR, f"run_{run_ts}")
    if not os.path.exists(run_folder):
        os.makedirs(run_folder)

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
            
            for record in records:
                source = record.get("source", "Unknown").capitalize()
                ts_str = record.get("collected_at")
                
                try:
                    event_date = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).strftime("%Y-%m-%d")
                except:
                    event_date = datetime.now().strftime("%Y-%m-%d")
                
                if source not in grouped_source_events:
                    grouped_source_events[source] = {
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
                    relevant_fields = ["asn", "country", "malware_family", "status", "hostname", "vt_score"]
                    richness = sum(1 for field in relevant_fields if enrichment.get(field))
                    
                    # Bonus de confiance si VirusTotal a scanné
                    if enrichment.get("passer_par_virustotal"):
                        richness += 2

                    confidence_pct = int((richness / (len(relevant_fields) + 2)) * 100)
                    
                    if confidence_pct >= 80: conf_level = "high"
                    elif confidence_pct >= 50: conf_level = "medium"
                    else: conf_level = "low"

                    m_type = get_misp_type(ioc_type, ioc_value)

                    main_attr = {
                        "type": m_type,
                        "value": ioc_value,
                        "to_ids": True,
                        "comment": "",
                        "Tag": [{"name": f"confidence:{conf_level}"}]
                    }

                    if enrichment.get("malware_family"):
                        main_attr["Tag"].append({"name": f"malware:{enrichment['malware_family'].lower()}"})
                    
                    # Tags VirusTotal
                    if enrichment.get("vt_malicious_count", 0) > 0:
                        main_attr["Tag"].append({"name": f"vt:malicious:{enrichment['vt_malicious_count']}"})
                        main_attr["Tag"].append({"name": "misp-galaxy:threat-actor=\"Malicious Activity\""})
                    
                    if enrichment.get("vt_tags"):
                        for tag in enrichment["vt_tags"][:3]: # Limiter à 3 tags pour pas surcharger
                            main_attr["Tag"].append({"name": f"vt:tag:{tag.lower()}"})

                    meta_parts = []
                    if enrichment.get("asn"): meta_parts.append(f"ASN: {enrichment['asn']}")
                    if enrichment.get("country"): meta_parts.append(f"Country: {enrichment['country']}")
                    
                    # Info VirusTotal dans les commentaires
                    if enrichment.get("passer_par_virustotal"):
                        vt_score = enrichment.get("vt_score", 0)
                        malicious = enrichment.get("vt_malicious_count", 0)
                        total = enrichment.get("vt_total_engines", 0)
                        meta_parts.append(f"VT Score: {vt_score} | VT Detections: {malicious}/{total}")

                    main_attr["comment"] = " | ".join(meta_parts) if meta_parts else f"Enriched from {source}"

                    grouped_source_events[source]["Event"]["Attribute"].append(main_attr)

            # --- Sauvegarde des fichiers par source ---
            for source_name, event_wrapper in grouped_source_events.items():
                src_folder = os.path.join(run_folder, source_name.lower())
                if not os.path.exists(src_folder): os.makedirs(src_folder)

                output_filename = f"misp_{source_name.lower()}_unified.json"
                output_path = os.path.join(src_folder, output_filename)
                
                manifest["generated_files"].append(f"{source_name.lower()}/{output_filename}")
                manifest["total_events"] += 1
                manifest["total_attributes"] += len(event_wrapper["Event"]["Attribute"])

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump([event_wrapper], f, indent=2)
                
                logger.info(f"  [OK] Generated 1 unified MISP event for {source_name} with {len(event_wrapper['Event']['Attribute'])} attributes")

            # --- Save current source results ---
            if source_events:
                src_folder = os.path.join(run_folder, source_name.lower())
                if not os.path.exists(src_folder): os.makedirs(src_folder)

                for key, events_list in source_events.items():
                    _, date = key.split("|")
                    output_filename = f"misp_{source_name.lower()}_{date}.json"
                    output_path = os.path.join(src_folder, output_filename)
                    
                    manifest["generated_files"].append(f"{source_name.lower()}/{output_filename}")
                    manifest["total_events"] += len(events_list)
                    manifest["total_attributes"] += sum(len(ev["Event"]["Attribute"]) for ev in events_list)

                    with open(output_path, "w", encoding="utf-8") as f:
                        json.dump(events_list, f, indent=2)
                    
                    logger.info(f"  [OK] Generated {len(events_list)} MISP events for {source_name} on {date}")

        except Exception as e:
            logger.error(f"Failed to process {filename}: {e}")

    # Save tracking manifest
    manifest_path = os.path.join(run_folder, "manifest_tracking.json")
    global_tracking_path = os.path.join(BASE_DIR, "normalisation", "tracking", f"run_{run_ts}.json")
    
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
