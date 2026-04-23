import os
import json

# --- 1. Clean up output_misp ---
misp_run_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_125208"
LIMIT_EVENTS = 3
LIMIT_ATTRS = 3

if os.path.exists(misp_run_path):
    for source_dir in os.listdir(misp_run_path):
        source_path = os.path.join(misp_run_path, source_dir)
        if not os.path.isdir(source_path):
            continue
            
        json_files = sorted([f for f in os.listdir(source_path) if f.endswith(".json")])
        if not json_files:
            continue
            
        # Keep only the first file
        file_to_keep = json_files[0]
        for f in json_files[1:]:
            os.remove(os.path.join(source_path, f))
            
        # Process the kept file
        target_file = os.path.join(source_path, file_to_keep)
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                # Limit events
                if len(data) > LIMIT_EVENTS:
                    data = data[:LIMIT_EVENTS]
                
                # Limit attributes per event
                for item in data:
                    event = item.get("Event", {})
                    attrs = event.get("Attribute", [])
                    if len(attrs) > LIMIT_ATTRS:
                        event["Attribute"] = attrs[:LIMIT_ATTRS]
                
                with open(target_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                print(f"[MISP] Kept and truncated {target_file}")
        except Exception as e:
            print(f"Error processing MISP file {target_file}: {e}")

# --- 2. Clean up output_normaliser ---
norm_run_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_normaliser\run_2026_04_23_125128"
LIMIT_NORM_RECORDS = 3

if os.path.exists(norm_run_path):
    for f in os.listdir(norm_run_path):
        if not f.endswith("_normalized.json"):
            continue
            
        path = os.path.join(norm_run_path, f)
        try:
            with open(path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            if isinstance(data, list):
                if len(data) > LIMIT_NORM_RECORDS:
                    data = data[:LIMIT_NORM_RECORDS]
                    
                with open(path, 'w', encoding='utf-8') as file:
                    json.dump(data, file, indent=2)
                print(f"[NORM] Truncated {path}")
        except Exception as e:
            print(f"Error processing Normalizer file {path}: {e}")
