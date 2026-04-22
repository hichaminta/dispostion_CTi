import os
import json
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger("Cleanup")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_EXTRACTED = os.path.join(BASE_DIR, "output_cve_ioc")
OUTPUT_ENRICHED = os.path.join(BASE_DIR, "output_enrichment")

INVALID_EXTENSIONS = {
    '.exe', '.dll', '.zip', '.rar', '.7z', '.tar', '.gz', '.file', '.arm', 
    '.mpsl', '.mips', '.hta', '.msi', '.bat', '.vbs', '.scr', '.js', '.elf', 
    '.sh', '.lnk', '.bin', '.dat', '.tmp', '.ulise', '.variant', '.png', '.jpg', '.jpeg'
}

def clean_file(file_path):
    if not os.path.exists(file_path):
        return False
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        modified = False
        new_data = []
        
        removed_count = 0
        
        for record in data:
            if "iocs" not in record:
                new_data.append(record)
                continue
                
            original_iocs = record["iocs"]
            new_iocs = []
            
            for ioc in original_iocs:
                val = ioc.get("value", "").lower()
                is_invalid = False
                
                # Check for invalid extensions in domains/urls
                if ioc.get("type") in ["domain", "domaine", "url"]:
                    if any(val.endswith(ext) for ext in INVALID_EXTENSIONS):
                        is_invalid = True
                
                if is_invalid:
                    removed_count += 1
                    modified = True
                else:
                    new_iocs.append(ioc)
            
            record["iocs"] = new_iocs
            new_data.append(record)
        
        if modified:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(new_data, f, ensure_ascii=False, indent=2)
            logger.info(f"  [CLEANED] {os.path.basename(file_path)}: Removed {removed_count} false positives.")
        
        return True
    except Exception as e:
        logger.error(f"Error cleaning {file_path}: {e}")
        return False

def main():
    logger.info("### STARTING CLEANUP OF FALSE POSITIVES (FILENAMES AS DOMAINS) ###")
    
    # 1. Clean extracted files
    if os.path.exists(OUTPUT_EXTRACTED):
        for f in os.listdir(OUTPUT_EXTRACTED):
            if f.endswith(".json"):
                clean_file(os.path.join(OUTPUT_EXTRACTED, f))
                
    # 2. Clean enriched files
    if os.path.exists(OUTPUT_ENRICHED):
        for f in os.listdir(OUTPUT_ENRICHED):
            if f.endswith(".json"):
                clean_file(os.path.join(OUTPUT_ENRICHED, f))
                
    logger.info("### CLEANUP COMPLETED ###")

if __name__ == "__main__":
    main()
