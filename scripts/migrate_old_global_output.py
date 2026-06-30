import os
import shutil

global_output = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\global_output"
old_extr = os.path.join(global_output, "output_cve_ioc")
old_enrich = os.path.join(global_output, "output_enrichment")

mapping = {
    "alienvault": "Otx alienvault",
    "cins_army": "CINS Army",
    "dfir_report": "The DFIR Report",
    "feodotracker": "feodotracker",
    "malwarebazaar": "MalwareBazaar Community API",
    "nvd": "NVd",
    "openphish": "OpenPhish",
    "phishtank": "PhishTank",
    "pulsedive": "pulsedive",
    "spamhaus": "Spamhaus",
    "threatfox": "ThreatFox",
    "urlhaus": "url"
}

def move_files(src_dir, target_stage):
    if not os.path.exists(src_dir):
        return
    for filename in os.listdir(src_dir):
        if filename.endswith(".json"):
            # try to find prefix
            for prefix, source_name in mapping.items():
                if filename.startswith(prefix):
                    target_dir = os.path.join(global_output, "sources", source_name, target_stage)
                    os.makedirs(target_dir, exist_ok=True)
                    src_file = os.path.join(src_dir, filename)
                    dest_file = os.path.join(target_dir, filename)
                    shutil.move(src_file, dest_file)
                    print(f"Moved {filename} to {target_dir}")
                    break

move_files(old_extr, "extraction")
move_files(old_enrich, "enrichment")
move_files(os.path.join(global_output, "..", "__TEMP__", "global_output", "output_cve_ioc"), "extraction")
move_files(os.path.join(global_output, "..", "__TEMP__", "global_output", "output_enrichment"), "enrichment")
