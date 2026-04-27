
import json
import os

nvd_raw_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\Sources_data\NVd\nvd_data.json"
nvd_extracted_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_cve_ioc\nvd_extracted.json"

def verify_files():
    print("--- Verification NVD Pipeline ---")
    
    if os.path.exists(nvd_raw_path):
        with open(nvd_raw_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
            print(f"[RAW] Nombre de CVEs dans nvd_data.json : {len(raw_data)}")
            if len(raw_data) > 0:
                print(f"      Exemple ID : {raw_data[0].get('cve_id')}")
    else:
        print("[ERROR] nvd_data.json introuvable.")

    if os.path.exists(nvd_extracted_path):
        with open(nvd_extracted_path, "r", encoding="utf-8") as f:
            extracted_data = json.load(f)
            print(f"[EXTRACTED] Nombre de records dans nvd_extracted.json : {len(extracted_data)}")
            if len(extracted_data) > 0:
                # nvd_extracted format is list of { record_id, cves: [ {id, ...} ], ... }
                first_record = extracted_data[0]
                cve_id = first_record.get('record_id')
                print(f"            Exemple Record ID : {cve_id}")
    else:
        print("[ERROR] nvd_extracted.json introuvable.")

if __name__ == "__main__":
    verify_files()
