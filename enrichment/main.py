import os
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EnrichmentOrchestrator")

def run_all():
    scripts_dir = os.path.join(os.path.dirname(__file__), 'scripts')
    
    if not os.path.exists(scripts_dir):
        logger.error(f"Scripts directory not found at {scripts_dir}")
        return

    logger.info("Starting global enrichment pipeline...")
    
    SKIP_LIST = ['nvd']
    
    for script_name in os.listdir(scripts_dir):
        if script_name.endswith('_enricher.py'):
            # Skip blacklisted sources
            if any(s.lower() in script_name.lower() for s in SKIP_LIST):
                logger.info(f"==> Skipping {script_name} (Blacklisted)")
                continue
                
            script_path = os.path.join(scripts_dir, script_name)
            logger.info(f"==> Launching {script_name}...")
            
            try:
                # Run each script synchronously for now. Can be async later if needed.
                # Use sys.executable to ensure we use the same Python interpreter
                import sys
                result = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    logger.info(f"==> Successfully completed {script_name}")
                else:
                    logger.error(f"==> Error in {script_name}:\n{result.stderr}")
                    
            except Exception as e:
                logger.error(f"Failed to run {script_name}: {e}")

    logger.info("Global enrichment pipeline finished.")

if __name__ == "__main__":
    run_all()
