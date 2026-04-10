import os

SOURCES = {
    "AbuseIPDB": "abuseipdb_extracted.json",
    "CINS Army": "cins_army_extracted.json",
    "MalwareBazaar Community API": "malwarebazaar_extracted.json",
    "OpenPhish": "openphish_extracted.json",
    "Otx alienvault": "alienvault_extracted.json",
    "PhishTank": "phishtank_extracted.json",
    "Spamhaus": "spamhaus_extracted.json",
    "ThreatFox": "threatfox_extracted.json",
    "VirusTotal": "virustotal_extracted.json",
    "feodotracker": "feodotracker_extracted.json",
    "pulsedive": "pulsedive_extracted.json",
    "url": "urlhaus_extracted.json"
}

TEMPLATE = """import os
import json
import logging
import sys

# Parent dir logic for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enrichers.nlp_enricher import NLPEnricher

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Enrichment.{source_name}")

# Paths (Relative to enrichment/scripts/source_enricher.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXTRACTED_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
ENRICHMENT_ROOT = os.path.join(BASE_DIR, "enrichment")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
TRACKING_DIR = os.path.join(ENRICHMENT_ROOT, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "{source_name}_tracking.json")

def ensure_dirs():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)

def process_source():
    ensure_dirs()
    
    file_path = os.path.join(EXTRACTED_DIR, "{file_name}")
    if not os.path.exists(file_path):
        logger.warning(f"Extracted file not found: {file_path}")
        return

    # Check tracking (last modified time) to avoid running again if not needed
    current_mtime = os.path.getmtime(file_path)
    
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, 'r', encoding='utf-8') as f:
                tracking_data = json.load(f)
                last_mtime = tracking_data.get("last_mtime")
                
                if last_mtime == current_mtime:
                    logger.info("Skipping {source_name}: No new modifications in extracted data.")
                    return
        except Exception:
            pass # Ignore and re-process if tracking file fails to load

    logger.info(f"Processing source array: {file_name}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read {file_path}: {e}")
        return

    enriched_data = []
    nlp_enricher = NLPEnricher()
    
    # data is expected to be a list of standardized extracted dicts
    if isinstance(data, list):
        for item in data:
            # First pass: NLP Enricher
            # The NLPEnricher now uses the 'source' field in the item to apply source-specific keywords
            enriched_item = nlp_enricher.enrich(item)
            
            # TODO: Future specific enrichers (e.g., GeoIP for CINS)
            # enriched_item = special_enricher.enrich(enriched_item)
            
            enriched_data.append(enriched_item)
    else:
        logger.error("Expected a list of extracted elements.")
        return

    out_file_name = "{file_name}".replace('_extracted.json', '_enriched.json')
    out_file_path = os.path.join(OUTPUT_DIR, out_file_name)
    
    with open(out_file_path, 'w', encoding='utf-8') as f:
        json.dump(enriched_data, f, indent=4)
        
    logger.info(f"Saved enriched data to {out_file_path}")
    
    # Save the new mtime in the tracking file
    with open(TRACKING_FILE, 'w', encoding='utf-8') as f:
        json.dump({"last_mtime": current_mtime}, f, indent=4)

if __name__ == "__main__":
    process_source()
"""

def generate_scripts():
    scripts_dir = os.path.join(os.path.dirname(__file__), "scripts")
    if not os.path.exists(scripts_dir):
        os.makedirs(scripts_dir)
        
    for source_name, file_name in SOURCES.items():
        script_name = file_name.replace("extracted.json", "enricher.py")
        script_path = os.path.join(scripts_dir, script_name)
        
        # Format the content
        content = TEMPLATE.replace("{source_name}", source_name.replace(" ", "_")).replace("{file_name}", file_name)
        
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Generated tracking template for {script_name}")

if __name__ == "__main__":
    generate_scripts()
