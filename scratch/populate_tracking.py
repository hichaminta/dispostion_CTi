import os
import json

base_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi"
output_enrichment = os.path.join(base_dir, "output_enrichment")
tracking_file = os.path.join(base_dir, "enrichment", "tracking", "enrichment_initialization.json")

tracking = {"last_run": None, "sources": {}}

for filename in os.listdir(output_enrichment):
    if filename.endswith("_enriched.json"):
        source_key = filename.replace("_enriched.json", "")
        file_path = os.path.join(output_enrichment, filename)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if data and isinstance(data, list):
                # Data is already sorted descending by initialize_enrichment.py
                latest_ts = data[0].get("collected_at", "")
                tracking["sources"][source_key] = latest_ts
        except Exception as e:
            print(f"Error processing {filename}: {e}")

from datetime import datetime
tracking["last_run"] = datetime.now().isoformat()

with open(tracking_file, "w", encoding="utf-8") as f:
    json.dump(tracking, f, indent=4)

print("Tracking file updated successfully.")
