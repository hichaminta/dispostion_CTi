import os
import re

sources_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\collection"
global_output_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\global_output\sources"

def main():
    for root, dirs, files in os.walk(sources_dir):
        if "script.py" in files:
            source_name = os.path.basename(root)
            script_path = os.path.join(root, "script.py")
            
            # The new collection dir
            collection_dir = os.path.join(global_output_dir, source_name, "collection")
            os.makedirs(collection_dir, exist_ok=True)
            
            # Create extraction and enrichment dirs as well
            os.makedirs(os.path.join(global_output_dir, source_name, "extraction"), exist_ok=True)
            os.makedirs(os.path.join(global_output_dir, source_name, "enrichment"), exist_ok=True)
            
            with open(script_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Find the old OUTPUT_JSON line, usually looks like:
            # OUTPUT_JSON = os.path.join(SCRIPT_DIR, "something_data.json")
            # We want to replace it with:
            # OUTPUT_JSON = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "global_output", "sources", "...", "collection", "something_data.json"))
            
            # Let's find the current filename
            match = re.search(r'OUTPUT_JSON\s*=\s*os\.path\.join\(SCRIPT_DIR,\s*["\']([^"\']+\.json)["\']\)', content)
            if not match:
                # Sometimes it's OUTPUT_FILE
                match = re.search(r'OUTPUT_FILE\s*=\s*os\.path\.join\(SCRIPT_DIR,\s*["\']([^"\']+\.json)["\']\)', content)
                
            if match:
                filename = match.group(1)
                new_line = f'OUTPUT_JSON = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "global_output", "sources", "{source_name}", "collection", "{filename}"))'
                
                # Replace it
                new_content = re.sub(r'OUTPUT_JSON\s*=\s*os\.path\.join\(SCRIPT_DIR,\s*["\'][^"\']+\.json["\']\)', new_line, content)
                new_content = re.sub(r'OUTPUT_FILE\s*=\s*os\.path\.join\(SCRIPT_DIR,\s*["\'][^"\']+\.json["\']\)', new_line.replace("OUTPUT_JSON", "OUTPUT_FILE"), new_content)
                
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated {source_name}/script.py -> {filename}")
                
                # Also, move the existing JSON file if it exists
                old_json_path = os.path.join(root, filename)
                new_json_path = os.path.join(collection_dir, filename)
                if os.path.exists(old_json_path):
                    try:
                        os.replace(old_json_path, new_json_path)
                        print(f"  Moved {filename} to new location")
                    except Exception as e:
                        print(f"  Error moving {filename}: {e}")
            else:
                print(f"Could not find OUTPUT_JSON in {source_name}/script.py")

if __name__ == "__main__":
    main()
