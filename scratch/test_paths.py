import os
import sys

# Simulate the paths in main.py
backend_app_dir = os.path.abspath(r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\backend\app")
OUTPUT_DIR = os.path.abspath(os.path.join(backend_app_dir, "..", "..", "output_cve_ioc"))

print(f"Computed OUTPUT_DIR: {OUTPUT_DIR}")
print(f"Exists: {os.path.exists(OUTPUT_DIR)}")

if os.path.exists(OUTPUT_DIR):
    print(f"Contents: {os.listdir(OUTPUT_DIR)}")

# Simulate the SOURCE_MAP check
SOURCE_MAP = {
    "AbuseIPDB":       {"id": "abuseipdb",     "folder": "AbuseIPDB",                    "extractor": "abuseipdb_extractor.py",      "output": "abuseipdb_extracted.json"},
    "AlienVault OTX":  {"id": "alienvault",    "folder": "Otx alienvault",               "extractor": "alienvault_extractor.py",     "output": "alienvault_extracted.json"},
    "CINS Army":       {"id": "cins_army",     "folder": "CINS Army",                    "extractor": "cins_army_extractor.py",      "output": "cins_army_extracted.json"},
    "FeodoTracker":    {"id": "feodotracker",  "folder": "feodotracker",                  "extractor": "feodotracker_extractor.py",   "output": "feodotracker_extracted.json"},
    "MalwareBazaar":   {"id": "malwarebazaar", "folder": "MalwareBazaar Community API",  "extractor": "malwarebazaar_extractor.py",  "output": "malwarebazaar_extracted.json"},
    "NVD":             {"id": "nvd",           "folder": "NVd",                           "extractor": "nvd_extractor.py",            "output": "nvd_extracted.json"},
    "OpenPhish":       {"id": "openphish",     "folder": "OpenPhish",                    "extractor": "openphish_extractor.py",      "output": "openphish_extracted.json"},
    "PhishTank":       {"id": "phishtank",     "folder": "PhishTank",                    "extractor": "phishtank_extractor.py",      "output": "phishtank_extracted.json"},
    "PulseDive":       {"id": "pulsedive",     "folder": "pulsedive",                    "extractor": "pulsedive_extractor.py",      "output": "pulsedive_extracted.json"},
    "Spamhaus":        {"id": "spamhaus",      "folder": "Spamhaus",                     "extractor": "spamhaus_extractor.py",       "output": "spamhaus_extracted.json"},
    "ThreatFox":       {"id": "threatfox",     "folder": "ThreatFox",                    "extractor": "threatfox_extractor.py",      "output": "threatfox_extracted.json"},
    "URLhaus":         {"id": "urlhaus",       "folder": "url",                          "extractor": "urlhaus_extractor.py",        "output": "urlhaus_extracted.json"},
    "VirusTotal":      {"id": "virustotal",    "folder": "VirusTotal",                   "extractor": "virustotal_extractor.py",     "output": "virustotal_extracted.json"},
}

found_sources = []
for src_name, info in SOURCE_MAP.items():
    filepath = os.path.join(OUTPUT_DIR, info["output"])
    if os.path.exists(filepath):
        found_sources.append(src_name)

print(f"Found sources: {found_sources}")
