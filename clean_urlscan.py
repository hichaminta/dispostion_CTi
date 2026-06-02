import os
import json

def clean_urlscan_data():
    output_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_enrichment"
    count = 0
    
    for filename in os.listdir(output_dir):
        if not filename.endswith("_enriched.json"):
            continue
            
        file_path = os.path.join(output_dir, filename)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue
            
        modified = False
        for record in data:
            # Nettoyer les attributs globaux
            if "attributes" in record:
                keys_to_del = [k for k in record["attributes"].keys() if k.startswith("urlscan_") or "urlscan" in k]
                for k in keys_to_del:
                    del record["attributes"][k]
                    modified = True
                    
            # Nettoyer les attributs de chaque IOC
            for ioc in record.get("iocs", []):
                enr = ioc.get("ioc_enrichment", {})
                keys_to_del = [k for k in enr.keys() if k.startswith("urlscan_") or k in ["passer_par_urlscan", "canne_par_url"]]
                for k in keys_to_del:
                    del enr[k]
                    modified = True
                    
        if modified:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                print(f"[OK] Nettoyé : {filename}")
                count += 1
            except Exception as e:
                print(f"Error writing {filename}: {e}")
                
    print(f"\nNettoyage terminé. {count} fichiers modifiés.")

if __name__ == "__main__":
    clean_urlscan_data()
