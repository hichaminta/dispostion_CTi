import os
import json

ENR_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_enrichment"

def verify_country_fields():
    if not os.path.exists(ENR_DIR):
        print(f"Directory not found: {ENR_DIR}")
        return

    files = [f for f in os.listdir(ENR_DIR) if f.endswith("_enriched.json")]
    
    for filename in files:
        path = os.path.join(ENR_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            total_records = len(data)
            with_country_attr = 0
            with_country_ioc = 0
            
            for record in data:
                # Check attributes
                attrs = record.get("attributes", {})
                if "country" in attrs or "country_code" in attrs:
                    with_country_attr += 1
                
                # Check IOCs
                for ioc in record.get("iocs", []):
                    enr = ioc.get("ioc_enrichment", {})
                    if "country" in enr or "country_code" in enr:
                        with_country_ioc += 1
                        break # Found one in this record
            
            print(f"File: {filename}")
            print(f"  Records: {total_records}")
            print(f"  Records with 'country' in attributes: {with_country_attr}")
            print(f"  Records with 'country' in IOC enrichment: {with_country_ioc}")
            print("-" * 30)
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    verify_country_fields()
