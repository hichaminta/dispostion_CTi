import os
import subprocess
import sys
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NLP_Only")

# Pipeline Configuration
SKIP_SOURCES = {"alienvault"}

def run_nlp(source_filter=None):

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    nlp_scripts_dir = os.path.join(base_dir, "nlp", "scripts")
    
    if not os.path.exists(nlp_scripts_dir):
        logger.error(f"NLP scripts directory not found at {nlp_scripts_dir}")
        return

    logger.info("### STARTING NLP-ONLY ENRICHMENT ###")
    
    scripts = sorted(os.listdir(nlp_scripts_dir))
    
    if source_filter:
        # Special Fix: 'Unified Extraction' means process all scripts
        if source_filter.lower() == "unified extraction":
            logger.info("### GLOBAL RUN: Unified Extraction Mode (All scripts) ###")
        else:
            # Normalize source filter (e.g. abuseipdb -> abuseipdb_enricher.py)
            target = f"{source_filter.lower()}_enricher.py"
            scripts = [s for s in scripts if s == target]
            if not scripts:
                logger.warning(f"No NLP script found for source: {source_filter}")
                return
            logger.info(f"Filtered run for source: {source_filter}")

    for script_name in scripts:
        if not script_name.endswith('_enricher.py'): continue
        if any(skip in script_name.lower() for skip in SKIP_SOURCES):
            logger.info(f"  [NLP] Skipping {script_name} (in SKIP_SOURCES)")
            continue
            
        script_path = os.path.join(nlp_scripts_dir, script_name)
        logger.info(f"  [NLP] Processing {script_name}...")
        try:
            # We don't pass -s to individual scripts because their filename already identifies the source
            subprocess.run([sys.executable, script_path], check=False)
        except Exception as e:
            logger.error(f"Failed to run {script_name}: {e}")
    
    logger.info("NLP enrichment completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run NLP enrichment (Optional: for a specific source)")
    parser.add_argument("-s", "--source", help="Only run for this specific source (e.g. abuseipdb)")
    args = parser.parse_args()
    
    run_nlp(source_filter=args.source)
