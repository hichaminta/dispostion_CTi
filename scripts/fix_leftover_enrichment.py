import os
import re
import glob

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"

def fix_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # If it defines ENRICHMENT_DIR, just leave it or define GLOBAL_SOURCES_DIR
    if "GLOBAL_SOURCES_DIR" not in content:
        content = content.replace("BASE_DIR = ", 'GLOBAL_SOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "global_output", "sources")\nBASE_DIR = ')
        content = content.replace("BASE_DIR = os.path.abspath(", 'GLOBAL_SOURCES_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "global_output", "sources")\nBASE_DIR = os.path.abspath(')

    # 1. Remove "if not os.path.exists(ENRICHMENT_DIR):" and its return/error
    content = re.sub(r'\s*if not os\.path\.exists\(ENRICHMENT_DIR\):\s*\n\s*logger\.error\([^)]+\)\s*\n\s*return\n', '\n', content)
    content = re.sub(r'\s*if not os\.path\.exists\(ENRICHMENT_DIR\):\s*\n\s*logger\.error\([^)]+\)\s*\n\s*sys\.exit\(1\)\n', '\n', content)
    
    # 2. Replace listdir logic with glob
    # json_files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith("_enriched.json")]
    old_listdir = re.compile(r'json_files\s*=\s*\[f for f in os\.listdir\(ENRICHMENT_DIR\) if f\.endswith\("_enriched\.json"\)\]')
    new_listdir = 'import glob\n    json_files = glob.glob(os.path.join(GLOBAL_SOURCES_DIR, "*", "enrichment", "*_enriched.json"))'
    content = old_listdir.sub(new_listdir, content)

    old_listdir2 = re.compile(r'files\s*=\s*\[f for f in os\.listdir\(ENRICHMENT_DIR\) if f\.endswith\("_enriched\.json"\)\]')
    new_listdir2 = 'import glob\n        files = glob.glob(os.path.join(GLOBAL_SOURCES_DIR, "*", "enrichment", "*_enriched.json"))'
    content = old_listdir2.sub(new_listdir2, content)

    # 3. Replace the inner loop logic
    # for filename in json_files:
    #     filepath = os.path.join(ENRICHMENT_DIR, filename)
    content = re.sub(r'for\s+(?:filename|fn)\s+in\s+(?:json_files|files):\s*\n\s*filepath\s*=\s*os\.path\.join\(ENRICHMENT_DIR,\s*(?:filename|fn)\)',
                     'for filepath in json_files:\n        filename = os.path.basename(filepath)', content)
    
    content = re.sub(r'for\s+(?:filename|fn)\s+in\s+files:\s*\n\s*filepath\s*=\s*os\.path\.join\(ENRICHMENT_DIR,\s*(?:filename|fn)\)',
                     'for filepath in files:\n            filename = os.path.basename(filepath)', content)

    # Specific fix for enrichir.py
    # logger.warning(f"Fichier {filename} introuvable dans {ENRICHMENT_DIR}")
    content = content.replace("dans {ENRICHMENT_DIR}", "dans extraction/enrichment")

    # Specific fix for classification/enrichir.py
    # enrichment_dir = args.dir if args.dir else ENRICHMENT_DIR
    content = content.replace('enrichment_dir = args.dir if args.dir else ENRICHMENT_DIR', 'enrichment_dir = args.dir if args.dir else GLOBAL_SOURCES_DIR')
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

for filepath in [
    os.path.join(enrichment_dir, "enrichment_ip", "enrichir_abuseipdb.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "nlp_enrichir.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "enrichir.py"),
    os.path.join(enrichment_dir, "classification", "enrichir.py")
]:
    if os.path.exists(filepath):
        fix_file(filepath)
        print(f"Fixed {filepath}")
