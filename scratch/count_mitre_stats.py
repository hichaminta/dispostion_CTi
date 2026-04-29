import os
import json
from collections import Counter

OUTPUT_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_mitre_attack"

def count_mitre_stats():
    if not os.path.exists(OUTPUT_DIR):
        print("Output directory not found.")
        return

    files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_mitre.json")]
    
    total_records = 0
    technique_counts = Counter()
    
    for filename in files:
        path = os.path.join(OUTPUT_DIR, filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for record in data:
                if "mitre_attack" in record:
                    total_records += 1
                    for tech in record["mitre_attack"]:
                        technique_counts[f"{tech['id']} ({tech['name']})"] += 1
        except Exception as e:
            print(f"Error reading {filename}: {e}")

    print(f"### MITRE ATT&CK Statistics ###")
    print(f"Total Enriched Records: {total_records}")
    print(f"Unique Techniques Found: {len(technique_counts)}")
    print("\nBreakdown by Technique:")
    for tech, count in technique_counts.most_common():
        print(f"- {tech}: {count}")

if __name__ == "__main__":
    count_mitre_stats()
