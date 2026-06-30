import os
import re

extractors_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\extraction_ioc_cve"

def main():
    for root, dirs, files in os.walk(extractors_dir):
        for file in files:
            if file.endswith("_extractor.py") and file != "base_extractor.py":
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extract the source name from SOURCE_DIR = os.path.join(BASE_DIR, "collection", "Source Name")
                # Or from hardcoded paths.
                match = re.search(r'SOURCE_DIR\s*=\s*os\.path\.join\(BASE_DIR,\s*"collection",\s*"([^"]+)"\)', content)
                if not match:
                    print(f"Could not find SOURCE_DIR in {file}")
                    continue
                
                source_name = match.group(1)
                
                # Replace SOURCE_DIR
                new_source_dir = f'SOURCE_DIR = os.path.join(BASE_DIR, "global_output", "sources", "{source_name}", "collection")'
                content = re.sub(r'SOURCE_DIR\s*=\s*os\.path\.join\(BASE_DIR,\s*"collection",\s*"[^"]+"\)', new_source_dir, content)
                
                # Replace OUTPUT_DIR
                new_output_dir = f'OUTPUT_DIR = os.path.join(BASE_DIR, "global_output", "sources", "{source_name}", "extraction")'
                content = re.sub(r'OUTPUT_DIR\s*=\s*os\.path\.join\(BASE_DIR,\s*(?:"__TEMP__/global_output/output_cve_ioc"|"global_output/output_cve_ioc"|"global_output", "output_cve_ioc")\)', new_output_dir, content)
                content = re.sub(r'OUTPUT_DIR\s*=\s*os\.path\.join\(BASE_DIR,\s*"[^"]*",\s*"global_output/output_cve_ioc"\)', new_output_dir, content)
                content = re.sub(r'OUTPUT_DIR\s*=\s*os\.path\.join\(BASE_DIR,\s*".*?global_output.*?"\)', new_output_dir, content) # Fallback

                # Wait, the exact string is: OUTPUT_DIR = os.path.join(BASE_DIR, "__TEMP__/global_output/output_cve_ioc")
                content = content.replace('OUTPUT_DIR = os.path.join(BASE_DIR, "__TEMP__/global_output/output_cve_ioc")', new_output_dir)
                content = content.replace('OUTPUT_DIR = os.path.join(BASE_DIR, "global_output", "output_cve_ioc")', new_output_dir)
                content = content.replace('OUTPUT_DIR = os.path.join(BASE_DIR, "global_output/output_cve_ioc")', new_output_dir)

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"Updated {file} for source {source_name}")

if __name__ == "__main__":
    main()
