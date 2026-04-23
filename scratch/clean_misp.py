import os
import json

directories = [
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\abuseipdb",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\alienvault",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\cins_army",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\feodotracker",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\malwarebazaar",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\openphish",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\phishtank",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\pulsedive",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\spamhaus",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\threatfox",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\urlhaus",
    r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_115425\virustotal"
]

def count_attributes(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                return 0
            total = 0
            for item in data:
                event = item.get("Event", {})
                attrs = event.get("Attribute", [])
                total += len(attrs)
            return total
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return float('inf')

for d in directories:
    if not os.path.exists(d):
        print(f"Directory not found: {d}")
        continue
    
    files = [f for f in os.listdir(d) if f.endswith(".json")]
    if not files:
        continue
    
    file_stats = []
    for f in files:
        path = os.path.join(d, f)
        count = count_attributes(path)
        file_stats.append((f, count))
    
    # Sort by count (fewest first)
    file_stats.sort(key=lambda x: x[1])
    
    # The winner
    best_file, best_count = file_stats[0]
    print(f"Directory: {os.path.basename(d)}")
    print(f"  Keeping: {best_file} ({best_count} attributes)")
    
    # Delete others
    to_delete = [f for f, count in file_stats[1:]]
    for f in to_delete:
        try:
            os.remove(os.path.join(d, f))
        except Exception as e:
            print(f"  Error deleting {f}: {e}")
    
    print(f"  Deleted {len(to_delete)} files.")
