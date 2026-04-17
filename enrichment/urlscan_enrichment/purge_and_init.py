import json
import os
import glob

# Paths
ENRICH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_enrichment"))
REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "scanner_par_url_io.json")

def cleanup():
    print(f"[*] Starting cleanup in {ENRICH_DIR}...")
    files = glob.glob(os.path.join(ENRICH_DIR, "*_enriched.json"))
    
    for f_path in files:
        modified = False
        try:
            with open(f_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for record in data:
                # 1. Clean up old url_scan blocks
                for ioc in record.get("iocs", []):
                    if "ioc_enrichment" in ioc and "url_scan" in ioc["ioc_enrichment"]:
                        # We remove all current ones to reset to the new 'flag' architecture
                        del ioc["ioc_enrichment"]["url_scan"]
                        modified = True
                
                # 2. Clean up old attributes if any
                if "attributes" in record:
                    for key in ["urlscan_score", "urlscan_verdict"]:
                        if key in record["attributes"]:
                            del record["attributes"][key]
                            modified = True
            
            if modified:
                with open(f_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                print(f" [OK] Purged: {os.path.basename(f_path)}")
        except Exception as e:
            print(f" [!] Error cleaning {f_path}: {e}")

def init_registry():
    if not os.path.exists(REGISTRY_PATH):
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=4)
        print(f"[*] Initialized Registry: {REGISTRY_PATH}")
    else:
        print(f"[*] Registry already exists: {REGISTRY_PATH}")

if __name__ == "__main__":
    print("--- URLScan Cleanup & Init Utility ---")
    print("[*] EXECUTING PURGE...")
    cleanup()
    init_registry()
    print("[*] DONE.")
