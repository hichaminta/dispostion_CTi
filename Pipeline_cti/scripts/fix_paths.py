import os
import glob
import re

scripts_dir = os.path.dirname(os.path.abspath(__file__))

# 1. Update run_pipeline.py
run_pipeline_path = os.path.join(scripts_dir, "run_pipeline.py")
with open(run_pipeline_path, "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace('os.path.join(BASE_DIR, "collection"', 'os.path.join(os.path.dirname(__file__), "collection"')
content = content.replace('os.path.join(BASE_DIR, "extraction_ioc_cve"', 'os.path.join(os.path.dirname(__file__), "extraction_ioc_cve"')
content = content.replace('os.path.join(BASE_DIR, "enrichment"', 'os.path.join(os.path.dirname(__file__), "enrichment"')
content = content.replace('os.path.join(BASE_DIR, "misp_integration"', 'os.path.join(os.path.dirname(__file__), "misp_integration"')

with open(run_pipeline_path, "w", encoding="utf-8") as f:
    f.write(content)

# 2. Update all the moved scripts
def fix_base_dir(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    changed = False
    
    # Remplacement 1: os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    # devient os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    if 'os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))' in content:
        content = content.replace(
            'os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))',
            'os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))'
        )
        changed = True

    # Remplacement 2: BASE_DIR = os.path.dirname(EXTRACTORS_DIR)
    # devient BASE_DIR = os.path.abspath(os.path.join(EXTRACTORS_DIR, "..", ".."))
    if 'BASE_DIR = os.path.dirname(EXTRACTORS_DIR)' in content:
        content = content.replace(
            'BASE_DIR = os.path.dirname(EXTRACTORS_DIR)',
            'BASE_DIR = os.path.abspath(os.path.join(EXTRACTORS_DIR, "..", ".."))'
        )
        changed = True

    # Remplacement 3: BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if used in enrichment
    # if it's the root dir, it should be adjusted. Wait, runner_intelligence.py is not here.
    
    if changed:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {filepath}")

for root, dirs, files in os.walk(scripts_dir):
    for name in files:
        if name.endswith(".py") and name != "fix_paths.py" and name != "run_pipeline.py":
            fix_base_dir(os.path.join(root, name))

print("All paths updated successfully.")
