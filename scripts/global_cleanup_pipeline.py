import json
import os
import sys
from datetime import datetime

# Root path for importing project modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from extraction_ioc_cve.base_extractor import BaseExtractor

EXTRACTION_DIR = "output_cve_ioc"
ENRICHMENT_DIR = "output_enrichment"

def cleanup_files(directory, is_enrichment=False):
    extractor = BaseExtractor()
    total_files = 0
    total_removed_iocs = 0
    total_removed_records = 0
    total_updated_fields = 0

    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return

    # Sort files to process in a predictable order
    files = sorted([f for f in os.listdir(directory) if f.endswith(".json")])
    
    for fn in files:
        filepath = os.path.join(directory, fn)
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Processing {fn} ({size_mb:.1f} MB)...")
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            modified_records = []
            file_modified = False
            file_removed_iocs = 0
            
            for record in records:
                original_ioc_count = len(record.get("iocs", []))
                
                # Filter IOCs
                filtered_iocs = []
                for ioc in record.get("iocs", []):
                    val = ioc.get("value", "").lower()
                    ioc_type = ioc.get("type")
                    
                    is_bad = False
                    if ioc_type in ["domaine", "url", "ip"]:
                        check_domain = val
                        if ioc_type == "url":
                            try:
                                from urllib.parse import urlparse
                                check_domain = urlparse(val).netloc.split(':')[0]
                            except: pass
                        
                        if extractor.is_whitelisted(check_domain):
                            is_bad = True
                    
                    if not is_bad:
                        # If enrichment layer: standardize 'country' field
                        if is_enrichment:
                            enr = ioc.get("ioc_enrichment", {})
                            if not enr.get("country") and enr.get("geography"):
                                enr["country"] = enr["geography"][0]
                                total_updated_fields += 1
                                file_modified = True
                            ioc["ioc_enrichment"] = enr
                            
                        filtered_iocs.append(ioc)
                    else:
                        file_removed_iocs += 1
                        file_modified = True
                
                # Keep record only if it has remaining intelligence (IOCs or CVEs)
                if filtered_iocs or record.get("cves"):
                    record["iocs"] = filtered_iocs
                    modified_records.append(record)
                else:
                    total_removed_records += 1
                    file_modified = True

            if file_modified:
                total_files += 1
                total_removed_iocs += file_removed_iocs
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(modified_records, f, indent=4, ensure_ascii=False)
                print(f"  -> {fn}: Removed {file_removed_iocs} IOCs. Records remaining: {len(modified_records)}")
            else:
                print(f"  -> {fn}: No changes needed.")

        except Exception as e:
            print(f"  !! Error processing {fn}: {e}")

    return total_files, total_removed_iocs, total_removed_records, total_updated_fields

def main():
    print("="*60)
    print("STARTING GLOBAL CTI DATA CLEANUP PIPELINE")
    print("="*60)
    
    # 1. Extraction Layer
    print("\n[STEP 1] Cleaning Extraction Layer...")
    e_files, e_iocs, e_recs, _ = cleanup_files(EXTRACTION_DIR, is_enrichment=False)
    
    # 2. Enrichment Layer
    print("\n[STEP 2] Cleaning & Standardizing Enrichment Layer...")
    r_files, r_iocs, r_recs, r_fields = cleanup_files(ENRICHMENT_DIR, is_enrichment=True)
    
    print("\n" + "="*60)
    print("PIPELINE EXECUTION COMPLETE")
    print(f"Total Files Updated     : {e_files + r_files}")
    print(f"Total Whitelisted IOCs  : {e_iocs + r_iocs}")
    print(f"Total Empty Records Purged: {e_recs + r_recs}")
    print(f"Total Country Fields Fixed: {r_fields}")
    print("="*60)

if __name__ == "__main__":
    main()
