import os
import re

filepath = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\scripts\global_cleanup_pipeline.py"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Replace variables
content = content.replace('EXTRACTION_DIR = "__TEMP__/global_output/output_cve_ioc"\nENRICHMENT_DIR = "__TEMP__/global_output/output_enrichment"', 
                          'GLOBAL_SOURCES_DIR = os.path.join(os.path.dirname(__file__), "..", "global_output", "sources")')

# Replace cleanup_files logic
old_cleanup = """def cleanup_files(directory, is_enrichment=False):
    extractor = BaseExtractor()
    total_files = 0
    total_removed_iocs = 0
    total_removed_records = 0
    total_updated_fields = 0

    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return

    # Sort files to process in a predictable order
    files = sorted([f for f in os.listdir(directory) if f.endswith(".json")])
    
    for fn in files:
        filepath = os.path.join(directory, fn)"""

new_cleanup = """def cleanup_files(stage_name, is_enrichment=False):
    extractor = BaseExtractor()
    total_files = 0
    total_removed_iocs = 0
    total_removed_records = 0
    total_updated_fields = 0

    import glob
    pattern = os.path.join(GLOBAL_SOURCES_DIR, "*", stage_name, "*.json")
    files = sorted(glob.glob(pattern))

    if not files:
        print(f"No files found for stage: {stage_name}")
        return 0, 0, 0, 0
    
    for filepath in files:
        fn = os.path.basename(filepath)"""

content = content.replace(old_cleanup, new_cleanup)

# Fix the return when directory not found logic which is now replaced, but wait, the return type is different?
# Python handles it.

# Update the main function calls
content = content.replace('e_files, e_iocs, e_recs, _ = cleanup_files(EXTRACTION_DIR, is_enrichment=False)', 
                          'e_files, e_iocs, e_recs, _ = cleanup_files("extraction", is_enrichment=False)')
content = content.replace('r_files, r_iocs, r_recs, r_fields = cleanup_files(ENRICHMENT_DIR, is_enrichment=True)',
                          'r_files, r_iocs, r_recs, r_fields = cleanup_files("enrichment", is_enrichment=True)')

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
