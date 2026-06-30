import os

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"

for filepath in [
    os.path.join(enrichment_dir, "enrichment_ip", "enrichir_abuseipdb.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "nlp_enrichir.py"),
    os.path.join(enrichment_dir, "enrichment_cve", "enrichir.py"),
    os.path.join(enrichment_dir, "classification", "enrichir.py")
]:
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        new_lines = []
        global_lines = []
        base_dir_line = None
        
        for line in lines:
            if line.startswith("GLOBAL_SOURCES_DIR ="):
                global_lines.append(line)
            elif line.startswith("BASE_DIR ="):
                base_dir_line = line
            else:
                new_lines.append(line)
                
        # Insert them correctly after "API_KEY = " or just somewhere top-level
        insert_idx = 0
        for i, line in enumerate(new_lines):
            if "API_KEY" in line or "os.getenv" in line or "load_dotenv" in line or "logging.getLogger" in line:
                insert_idx = i + 1
        
        if base_dir_line:
            new_lines.insert(insert_idx, base_dir_line)
            if global_lines:
                # Add only the first global line since we might have duplicates
                new_lines.insert(insert_idx + 1, global_lines[-1])
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print(f"Fixed ordering in {filepath}")
