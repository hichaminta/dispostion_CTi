import os
import json
import logging
import re
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MITRE_Mapper")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_mitre_attack")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Simplified MITRE ATT&CK Mapping
# Key: keyword or regex, Value: list of (Technique ID, Technique Name)
MAPPING_RULES = {
    "keywords": {
        r"phishing|phishtank|openphish": [("T1566", "Phishing")],
        r"malware|payload|delivery|dropper": [("TA0002", "Execution"), ("T1204", "User Execution")],
        r"c2|command and control|botnet|cc": [("TA0011", "Command and Control"), ("T1071", "Application Layer Protocol")],
        r"brute force|password|credential|login": [("T1110", "Brute Force"), ("TA0006", "Credential Access")],
        r"scanner|scanning|vulnerability|exploit": [("T1595", "Active Scanning"), ("T1190", "Exploit Public-Facing Application")],
        r"exfiltration|leak|stolen": [("TA0010", "Exfiltration")],
        r"persistence|startup|registry": [("TA0003", "Persistence")],
        r"powershell|ps1|posh": [("T1059.001", "PowerShell")],
        r"wmi|wmiprvse": [("T1047", "Windows Management Instrumentation")],
        r"evasion|sandbox|debug|virtualization": [("T1497", "Virtualization/Sandbox Evasion")],
        r"spreader|propagation|lateral": [("T1105", "Ingress Tool Transfer"), ("T1570", "Lateral Tool Transfer")],
        r"injection|hooking": [("T1055", "Process Injection")],
        r"macro|office|vba|excel|word": [("T1059.005", "Visual Basic")],
        r"javascript|js-embedded|script": [("T1059.007", "JavaScript")],
        r"ransomware|crypto|encryptor": [("T1486", "Data Encrypted for Impact")],
    },
    "cve_types": {
        "XSS": [("T1189", "Drive-by Compromise")],
        "Injection": [("T1190", "Exploit Public-Facing Application")],
        "RCE": [("T1210", "Exploitation of Remote Services")],
        "Path Traversal": [("T1083", "File and Directory Discovery")],
        "Privilege Escalation": [("TA0004", "Privilege Escalation")],
        "Access Control": [("T1078", "Valid Accounts")],
    }
}

def map_record(record):
    techniques = set()
    
    # 1. Collect all possible text sources from the record
    search_text = []
    
    # Root tags
    search_text.extend(record.get("tags", []))
    
    # Description
    search_text.append(record.get("description", ""))
    
    # Threat Type
    search_text.append(record.get("attributes", {}).get("threat_type", ""))
    
    # Malware Family
    search_text.append(record.get("attributes", {}).get("malware_family", ""))
    
    # 2. Enrich from IOC-specific data
    for ioc in record.get("iocs", []):
        enrichment = ioc.get("ioc_enrichment", {})
        # Other potential fields
        search_text.append(enrichment.get("threat_type", ""))
        search_text.append(enrichment.get("malware_family", ""))
        search_text.extend(enrichment.get("vt_tags", []))
    
    # Normalize text
    full_text = " ".join([str(t) for t in search_text if t]).lower()
    
    # 3. Apply Keyword Rules
    for pattern, tech_list in MAPPING_RULES["keywords"].items():
        if re.search(pattern, full_text):
            for tech in tech_list:
                techniques.add(tech)
                
    # 4. Apply CVE Type Rules (for description specifically)
    desc = record.get("description", "").lower()
    for cve_type, tech_list in MAPPING_RULES["cve_types"].items():
        if cve_type.lower() in desc:
            for tech in tech_list:
                techniques.add(tech)

    if techniques:
        # Format as list of dicts for easy dashboard/MISP use
        record["mitre_attack"] = [
            {"id": t[0], "name": t[1]} for t in sorted(list(techniques))
        ]
        return True
    return False

def process_files():
    if not os.path.exists(INPUT_DIR):
        logger.error(f"Input directory not found: {INPUT_DIR}")
        return

    files = [f for f in os.listdir(INPUT_DIR) if f.endswith("_enriched.json")]
    logger.info(f"### MITRE ATT&CK MAPPING STARTED ({len(files)} files) ###")

    total_mapped = 0
    
    for filename in files:
        file_path = os.path.join(INPUT_DIR, filename)
        output_path = os.path.join(OUTPUT_DIR, filename.replace("_enriched.json", "_mitre.json"))
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            mapped_in_file = 0
            for record in data:
                if map_record(record):
                    mapped_in_file += 1
            
            if mapped_in_file > 0:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"  [OK] {filename}: {mapped_in_file} records mapped. Saved to {os.path.basename(output_path)}")
                total_mapped += mapped_in_file
            else:
                logger.info(f"  [SKIP] {filename}: No mappings found.")
                
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

    logger.info(f"### MITRE ATT&CK MAPPING COMPLETED: {total_mapped} records enriched ###")

if __name__ == "__main__":
    process_files()
