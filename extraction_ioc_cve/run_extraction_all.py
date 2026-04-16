import os
import subprocess
import sys
import time

def run_all():
    # The script is now inside the extractors directory
    extractors_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = sorted([f for f in os.listdir(extractors_dir) 
                    if f.endswith("_extractor.py") and f != "base_extractor.py" and "alienvault" not in f.lower()])
    
    print(f"Starting unified extraction for {len(scripts)} sources (AlienVault skipped)...")
    start_time = time.time()
    
    for script in scripts:
        script_path = os.path.join(extractors_dir, script)
        print(f"\n--- Running {script} ---")
        try:
            # Use sys.executable to run with the same python environment
            # Pass any arguments received by run_all.py to the sub-scripts (e.g. --full)
            cmd = [sys.executable, script_path] + sys.argv[1:]
            subprocess.run(cmd, check=True, cwd=os.path.dirname(extractors_dir))
        except subprocess.CalledProcessError as e:
            print(f"Error running {script}: {e}")
        except Exception as e:
            print(f"Unexpected error for {script}: {e}")
            
    end_time = time.time()
    print(f"\nAll extractions completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    run_all()
