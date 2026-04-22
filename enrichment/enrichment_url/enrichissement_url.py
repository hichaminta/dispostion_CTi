import os
import sys
import subprocess
import argparse
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("URLEnrichment")

def run_script(script_path, source=None):
    if not os.path.exists(script_path):
        logger.error(f"Script NOT FOUND: {script_path}")
        return False
    
    cmd = [sys.executable, script_path]
    if source:
        cmd.extend(["-s", source])
        
    logger.info(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Execution failed for {script_path}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Unified URL Enrichment Orchestrator")
    parser.add_argument("--mode", choices=["urlscan", "fallback", "both"], default="both", 
                        help="Enrichment mode: urlscan (Stage 3), fallback (Stage 4), or both (Complete)")
    parser.add_argument("-s", "--source", help="Filter by specific source")
    
    args = parser.parse_args()
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    urlscan_script = os.path.join(base_dir, "enrichir_exclusive_urlscan.py")
    fallback_script = os.path.join(base_dir, "enrichir_fallback.py")
    
    logger.info(f"### URL ENRICHMENT MODE: {args.mode.upper()} ###")
    
    success = True
    
    if args.mode in ["urlscan", "both"]:
        logger.info("--- [STAGE 3] URLScan Analysis ---")
        if not run_script(urlscan_script, args.source):
            success = False
            
    if args.mode in ["fallback", "both"]:
        logger.info("--- [STAGE 4] Fallback Enrichment ---")
        if not run_script(fallback_script, args.source):
            success = False
            
    logger.info(f"### URL ENRICHMENT COMPLETED (Status: {'OK' if success else 'PARTIAL/FAILED'}) ###")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
