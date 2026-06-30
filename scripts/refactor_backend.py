import os
import re

backend_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\backend\app"

def refactor_main():
    main_path = os.path.join(backend_dir, "main.py")
    with open(main_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Replace global vars
    content = re.sub(
        r'OUTPUT_DIR\s*=\s*os\.path\.abspath\([^)]+\)', 
        'GLOBAL_SOURCES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "global_output", "sources"))', 
        content, 
        count=1
    )
    content = re.sub(r'ENRICHMENT_DIR\s*=\s*os\.path\.abspath\([^)]+\)\n', '', content)
    content = re.sub(r'MITRE_DIR\s*=\s*os\.path\.abspath\([^)]+\)[^\n]*\n', '', content)
    content = re.sub(r'CORRELATION_DIR\s*=\s*os\.path\.abspath\([^)]+\)', 
                     'CORRELATION_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "global_output", "output_correlation"))', 
                     content)
    
    # Replace filepath = os.path.join(OUTPUT_DIR, info["output"])
    content = content.replace(
        'filepath = os.path.join(OUTPUT_DIR, info["output"])',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, src_name, "extraction", info["output"])'
    )
    
    # For the case where src_name is not available directly (like info is given but no src_name):
    # def get_data(source: str, ...
    # info = worker.SOURCE_MAP.get(source)
    # filepath = os.path.join(OUTPUT_DIR, info["output"])
    content = content.replace(
        'filepath = os.path.join(OUTPUT_DIR, info["output"])',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, source, "extraction", info["output"])'
    )
    # Re-check where it was used
    
    # ENRICHMENT_DIR uses
    content = content.replace(
        'filepath = os.path.join(ENRICHMENT_DIR, fn)',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, source, "enrichment", fn)'
    )
    content = content.replace(
        'filepath = os.path.join(ENRICHMENT_DIR, enriched_fn)',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, src_name if "src_name" in locals() else source, "enrichment", enriched_fn)'
    )
    
    # MITRE uses (Mitre now stays in enrichment dir?) Wait, mitre mapper in classification creates `_mitre.json`?
    # Where does mitre mapper output? It says `OUTPUT_DIR = INPUT_DIR  # Update in place in __TEMP__/global_output/output_enrichment`.
    # So mitre mapper modifies `_enriched.json` in place or outputs `_mitre.json` in enrichment dir?
    content = content.replace(
        'filepath = os.path.join(MITRE_DIR, mitre_fn)',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, src_name if "src_name" in locals() else source, "enrichment", mitre_fn)'
    )
    content = content.replace(
        'filepath = os.path.join(MITRE_DIR, fn)',
        'filepath = os.path.join(GLOBAL_SOURCES_DIR, source, "enrichment", fn)'
    )
    
    # Replace checking if dir exists
    content = content.replace('if os.path.exists(OUTPUT_DIR):', 'if os.path.exists(GLOBAL_SOURCES_DIR):')
    content = content.replace('if os.path.exists(ENRICHMENT_DIR):', 'if os.path.exists(GLOBAL_SOURCES_DIR):')
    content = content.replace('if os.path.exists(MITRE_DIR):', 'if os.path.exists(GLOBAL_SOURCES_DIR):')
    
    # Replace listdir logic for ENRICHMENT_DIR
    content = re.sub(r'for fn in os\.listdir\(ENRICHMENT_DIR\):', r'import glob\n        for filepath in glob.glob(os.path.join(GLOBAL_SOURCES_DIR, source, "enrichment", "*_enriched.json")):\n            fn = os.path.basename(filepath)', content)
    
    content = re.sub(r'for fn in os\.listdir\(MITRE_DIR\):', r'import glob\n        for filepath in glob.glob(os.path.join(GLOBAL_SOURCES_DIR, source, "enrichment", "*_mitre.json")):\n            fn = os.path.basename(filepath)', content)

    # In stats route:
    content = content.replace(
        'src_name if "src_name" in locals() else source',
        'src_name'
    )
    
    with open(main_path, "w", encoding="utf-8") as f:
        f.write(content)

def refactor_worker():
    worker_path = os.path.join(backend_dir, "worker.py")
    with open(worker_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r'OUTPUT_DIR\s*=\s*os\.path\.join\([^)]+\)', 
        'GLOBAL_SOURCES_DIR = os.path.join(PROJECT_ROOT, "global_output", "sources")', 
        content
    )
    
    # In `_count_ioc_cve(source_name: str)`
    old_count = """    if info:
        filepath = os.path.join(OUTPUT_DIR, info["output"])"""
    new_count = """    if info:
        filepath = os.path.join(GLOBAL_SOURCES_DIR, source_name, "extraction", info["output"])"""
    content = content.replace(old_count, new_count)

    old_total_count = """            for src_name, src_info in SOURCE_MAP.items():
                fp = os.path.join(OUTPUT_DIR, src_info["output"])"""
    new_total_count = """            for src_name, src_info in SOURCE_MAP.items():
                fp = os.path.join(GLOBAL_SOURCES_DIR, src_name, "extraction", src_info["output"])"""
    content = content.replace(old_total_count, new_total_count)

    content = content.replace('if os.path.exists(OUTPUT_DIR):', 'if os.path.exists(GLOBAL_SOURCES_DIR):')

    with open(worker_path, "w", encoding="utf-8") as f:
        f.write(content)

if __name__ == "__main__":
    refactor_main()
    refactor_worker()
    print("Backend refactored")
