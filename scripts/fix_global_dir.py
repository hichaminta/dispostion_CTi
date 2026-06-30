import os
import glob

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"

for filepath in [
    os.path.join(enrichment_dir, "enrichment_ip", "enrichir_abuseipdb.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "nlp_enrichir.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "enrichir.py"),
    os.path.join(enrichment_dir, "classification", "enrichir.py")
]:
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        content = content.replace(
            'GLOBAL_SOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "global_output", "sources")',
            'GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "global_output", "sources")'
        )
        content = content.replace(
            'GLOBAL_SOURCES_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "global_output", "sources")',
            'GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "global_output", "sources")'
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Fixed GLOBAL_SOURCES_DIR in {filepath}")
