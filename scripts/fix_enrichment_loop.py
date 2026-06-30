import os

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"

def fix_script(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # The typical loop is `for filename in files:` or `for filepath in files:`
    # Since `glob.glob` returns a list of full filepaths, `filename` is actually `filepath`.
    # Let's just fix it by injecting a line that reassigns `filename` and `file_path`.
    
    # In geolocalisation/enrichir.py:
    content = content.replace(
        "for filename in files:\n        source = get_source_from_filename(filename)\n        file_path = os.path.join(OUTPUT_DIR, filename)",
        "for file_path in files:\n        filename = os.path.basename(file_path)\n        source = os.path.basename(os.path.dirname(os.path.dirname(file_path)))"
    )

    # In classification/mitre_mapper.py
    content = content.replace(
        "for filename in all_files:\n        filepath = os.path.join(INPUT_DIR, filename)",
        "for filepath in all_files:\n        filename = os.path.basename(filepath)\n        source = os.path.basename(os.path.dirname(os.path.dirname(filepath)))"
    )
    
    # General fix if someone uses filename from glob
    # Actually I should also fix how `source` is extracted!
    # In the old way, `source = filename.replace("_enriched.json", "")` etc.
    # Now it's `source = os.path.basename(os.path.dirname(os.path.dirname(filepath)))`
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

for root, dirs, files in os.walk(enrichment_dir):
    for f in files:
        if f.endswith(".py"):
            fix_script(os.path.join(root, f))
