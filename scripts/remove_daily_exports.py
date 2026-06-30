import os
import re
import glob

sources_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\collection"

# Pattern to find dated json files like threatfox_data_2026-06-23.json
dated_json_pattern = re.compile(r".*_\d{4}-\d{2}-\d{2}.*\.json$")

# Patterns to remove in code
code_patterns_to_remove = [
    re.compile(r"today_str\s*=\s*datetime\.now\(\)\.strftime\([^)]+\)\n?"),
    re.compile(r"DAILY_OUTPUT_JSON\s*=\s*os\.path\.join\(SCRIPT_DIR,[^)]+\)\n?"),
    re.compile(r"if new_records(_total)?:\n\s+logging\.info\(f?\"Export journalier.*\n\s+save_json_atomic\(new_records(_total)?, DAILY_OUTPUT_JSON\)\n?"),
]

for root, dirs, files in os.walk(sources_dir):
    for file in files:
        filepath = os.path.join(root, file)
        
        # 1. Delete dated json files
        if file.endswith(".json") and dated_json_pattern.match(file):
            print(f"Deleting dated JSON: {filepath}")
            try:
                os.remove(filepath)
            except Exception as e:
                print(f"Failed to delete {filepath}: {e}")
                
        # 2. Modify script.py
        if file == "script.py":
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            
            original_content = content
            
            # Simple line replacements for standard occurrences
            lines = content.split('\n')
            new_lines = []
            skip_next = 0
            for i, line in enumerate(lines):
                if skip_next > 0:
                    skip_next -= 1
                    continue
                
                # Check for daily export block
                if line.strip() == "if new_records_total:" or line.strip() == "if new_records:":
                    # Check if next lines are about daily export
                    is_daily_block = False
                    for j in range(1, 4):
                        if i+j < len(lines) and "DAILY_OUTPUT_JSON" in lines[i+j]:
                            is_daily_block = True
                            break
                    if is_daily_block:
                        # Skip this block (usually 2-3 lines inside the if)
                        skip_next = 2 # skips the next 2 lines inside the block
                        continue
                
                if "today_str =" in line and "strftime" in line:
                    continue
                if "DAILY_OUTPUT_JSON =" in line:
                    continue
                
                new_lines.append(line)
                
            new_content = '\n'.join(new_lines)
            
            if new_content != original_content:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated {filepath}")
