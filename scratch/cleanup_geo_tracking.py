import os
import json

TRACKING_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment\tracking"

def cleanup_geo_tracking():
    if not os.path.exists(TRACKING_DIR):
        print(f"Directory not found: {TRACKING_DIR}")
        return

    files = [f for f in os.listdir(TRACKING_DIR) if f.endswith("_tracking.json")]
    
    for filename in files:
        path = os.path.join(TRACKING_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if "geo" in data:
                del data["geo"]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                print(f"Removed 'geo' tracking from {filename}")
            else:
                print(f"No 'geo' section in {filename}")
        except Exception as e:
            print(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    cleanup_geo_tracking()
