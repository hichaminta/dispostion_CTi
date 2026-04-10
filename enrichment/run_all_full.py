import os
import subprocess
import sys

extractors_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\extraction_ioc_cve"
scripts = sorted([f for f in os.listdir(extractors_dir) 
                if f.endswith("_extractor.py") and f != "base_extractor.py"])

for script in scripts:
    script_path = os.path.join(extractors_dir, script)
    print(f"Running {script} --full...")
    try:
        subprocess.run([sys.executable, script_path, "--full"], check=True, cwd=os.path.dirname(extractors_dir))
    except Exception as e:
        print(f"Error running {script}: {e}")

print("Done.")
