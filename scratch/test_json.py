import os
import json

ENRICHMENT_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_enrichment"

for fn in os.listdir(ENRICHMENT_DIR):
    if not fn.endswith(".json"): continue
    filepath = os.path.join(ENRICHMENT_DIR, fn)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            json.load(f)
        print(f"OK: {fn}")
    except Exception as e:
        print(f"ERROR: {fn} -> {e}")
