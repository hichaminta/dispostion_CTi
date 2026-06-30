import os
import re

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"

def refactor_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original_content = content

    # Replace ENRICHMENT_DIR definition if it exists
    content = re.sub(r'ENRICHMENT_DIR\s*=\s*os\.path\.join\([^)]+\)', '', content)
    # Replace OUTPUT_DIR in some scripts that use it instead of ENRICHMENT_DIR (except in initialize_enrichment.py which we will handle manually)
    
    if "initialize_enrichment.py" not in filepath and "main.py" not in filepath:
        # For typical enrichir scripts:
        # json_files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith(".json")]
        # or similar.
        
        # Replace listdir loop
        loop_pattern = re.compile(
            r'json_files\s*=\s*\[f for f in os\.listdir\((?:ENRICHMENT_DIR|OUTPUT_DIR|enr_dir)\) if f\.endswith\("\.json"\)\]\n\s*.*?\n\s*for filename in json_files:\n\s*.*?filepath\s*=\s*os\.path\.join\((?:ENRICHMENT_DIR|OUTPUT_DIR|enr_dir),\s*filename\)', 
            re.DOTALL
        )
        
        replacement = """import glob
    json_files = glob.glob(os.path.join(BASE_DIR, "global_output", "sources", "*", "enrichment", "*.json"))
    for filepath in json_files:
        filename = os.path.basename(filepath)"""
        
        content = loop_pattern.sub(replacement, content)

        # Another variation:
        # files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
        # for filename in files:
        #    filepath = os.path.join(OUTPUT_DIR, filename)
        loop_pattern_2 = re.compile(
            r'files\s*=\s*\[f for f in os\.listdir\((?:ENRICHMENT_DIR|OUTPUT_DIR|enr_dir)\) if f\.endswith\("\.json"\)\]\n.*?for filename in files:\n\s*filepath\s*=\s*os\.path\.join\((?:ENRICHMENT_DIR|OUTPUT_DIR|enr_dir),\s*filename\)', 
            re.DOTALL
        )
        replacement_2 = """import glob
    files = glob.glob(os.path.join(BASE_DIR, "global_output", "sources", "*", "enrichment", "*.json"))
    for filepath in files:
        filename = os.path.basename(filepath)"""
        
        content = loop_pattern_2.sub(replacement_2, content)

    if content != original_content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Refactored {filepath}")

def main():
    for root, dirs, files in os.walk(enrichment_dir):
        for file in files:
            if file.endswith(".py"):
                refactor_file(os.path.join(root, file))

if __name__ == "__main__":
    main()
