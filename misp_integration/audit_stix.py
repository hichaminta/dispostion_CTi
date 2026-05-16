import json
import os

INPUT_FILE = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_correlation\correlated_events_soc_enriched.json"
STIX_FILE = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_correlation\stix_export.json"

with open(INPUT_FILE, 'r', encoding='utf-8') as f:
    input_data = json.load(f)

with open(STIX_FILE, 'r', encoding='utf-8') as f:
    stix_bundle = json.load(f)

stix_objects = stix_bundle.get("objects", [])
indicators = [o for o in stix_objects if o["type"] == "indicator"]

print(f"--- Deep IOC Enrichment Check ---")
# On cherche un IOC avec VT dans l'input
found_vt = False
for ev in input_data:
    for ioc in ev.get('iocs', []):
        enrich = ioc.get('enrichment', {})
        if 'vt_malicious_count' in enrich:
            print(f"Found IOC with VT: {ioc['value']} in event {ev['event_name']}")
            stix_ioc = next((o for o in indicators if ioc['value'] in o['name']), None)
            if stix_ioc:
                print(f"  STIX Description:\n{stix_ioc['description']}")
                if 'VirusTotal' in stix_ioc['description']:
                    print("  [OK] VirusTotal data is present.")
                else:
                    print("  [ERROR] VirusTotal data is MISSING!")
            found_vt = True
            break
    if found_vt: break

if not found_vt:
    print("No IOC with VT found in input data.")
