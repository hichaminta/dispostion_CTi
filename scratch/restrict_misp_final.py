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

LIMIT_EVENTS = 3
LIMIT_ATTRS = 3

for d in directories:
    if not os.path.exists(d):
        continue
    
    for f in os.listdir(d):
        if not f.endswith(".json"):
            continue
            
        path = os.path.join(d, f)
        try:
            with open(path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            if not isinstance(data, list):
                continue
            
            # 1. Limit the number of events in the file
            if len(data) > LIMIT_EVENTS:
                data = data[:LIMIT_EVENTS]
                
            # 2. Limit attributes inside each event
            for item in data:
                event = item.get("Event", {})
                attrs = event.get("Attribute", [])
                if len(attrs) > LIMIT_ATTRS:
                    event["Attribute"] = attrs[:LIMIT_ATTRS]
            
            with open(path, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=2)
            print(f"File {path} restricted to {LIMIT_EVENTS} events.")
                
        except Exception as e:
            print(f"Error processing {path}: {e}")
