import json
import os
import sys

# Add root dir to path to import BaseExtractor
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from extraction_ioc_cve.base_extractor import BaseExtractor

ENRICHMENT_DIR = "output_enrichment"

def fix_data():
    extractor = BaseExtractor()
    total_files = 0
    total_removed = 0
    total_updated = 0

    if not os.path.exists(ENRICHMENT_DIR):
        print(f"Error: {ENRICHMENT_DIR} not found.")
        return

    for fn in sorted(os.listdir(ENRICHMENT_DIR)):
        if not fn.endswith("_enriched.json"):
            continue
        
        filepath = os.path.join(ENRICHMENT_DIR, fn)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] STARTING: {fn} ({os.path.getsize(filepath) / 1024 / 1024:.1f} MB)")
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            modified_records = []
            file_modified = False
            removed_in_file = 0
            updated_in_file = 0
            
            for record in records:
                # 1. Filtration by Whitelist
                iocs = record.get("iocs", [])
                original_ioc_count = len(iocs)
                
                # Filter out whitelisted domains/URLs
                filtered_iocs = []
                for ioc in iocs:
                    val = ioc.get("value", "").lower()
                    ioc_type = ioc.get("type")
                    
                    is_bad = False
                    if ioc_type in ["domaine", "url", "ip"]:
                        check_val = val
                        if ioc_type == "url":
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(val)
                                check_val = parsed.netloc.split(':')[0]
                            except: pass
                        
                        if extractor.is_whitelisted(check_val):
                            is_bad = True
                    
                    if not is_bad:
                        # 2. Add 'country' field to remaining IOCs
                        enr = ioc.get("ioc_enrichment", {})
                        if not enr.get("country") and enr.get("geography"):
                            enr["country"] = enr.get("geography")[0]
                            updated_in_file += 1
                            file_modified = True
                        
                        ioc["ioc_enrichment"] = enr
                        filtered_iocs.append(ioc)
                    else:
                        removed_in_file += 1
                        file_modified = True
                
                # Keep record only if it still has useful data
                if filtered_iocs or record.get("cves"):
                    record["iocs"] = filtered_iocs
                    modified_records.append(record)
                else:
                    file_modified = True
            
            if file_modified:
                print(f"  -> Writing changes: Removed {removed_in_file}, Updated {updated_in_file}")
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(modified_records, f, indent=4, ensure_ascii=False)
                total_files += 1
                total_removed += removed_in_file
                total_updated += updated_in_file
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] FINISHED: {fn}")
            
        except Exception as e:
            print(f"Error processing {fn}: {e}")

    print("\n" + "="*40)
    print("GLOBAL MIGRATION COMPLETE")
    print(f"Files modified    : {total_files}")
    print(f"Benign IOCs removed: {total_removed}")
    print(f"Fields updated    : {total_updated}")
    print("="*40)

if __name__ == "__main__":
    from datetime import datetime
    fix_data()
