import os
import re

enrichment_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment"
global_output_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\global_output\sources"

def main():
    for root, dirs, files in os.walk(enrichment_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                # Common variables to refactor:
                # ENRICHMENT_DIR = ...
                # OUTPUT_CVE_IOC_DIR = ...
                
                # We need to replace the logic of `for filename in os.listdir(ENRICHMENT_DIR):`
                # with `import glob; for filepath in glob.glob(os.path.join(GLOBAL_DIR, "sources", "*", "enrichment", "*.json")):`
                # This is tricky to do with regex alone.
                
                # Let's see if we can just define a helper in utils to get these files and import it.
                pass

if __name__ == "__main__":
    main()
