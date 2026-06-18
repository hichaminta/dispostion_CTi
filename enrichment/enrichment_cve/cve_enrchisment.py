import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import subprocess
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger("CVE_Enrichment_Orchestrator")

def run_cve_pipeline():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    args = sys.argv[1:]
    
    # 1. Standard CVE Enrichment (NVD/NIST)
    enrich_script = os.path.join(base_dir, "enrichir.py")
    # 2. NLP CVE Analysis (Entities extraction)
    nlp_script = os.path.join(base_dir, "nlp_enrichir.py")

    logger.info("### STARTING CONSOLIDATED CVE ENRICHMENT PIPELINE ###")

    # STAGE 1: ENRICHMENT
    if os.path.exists(enrich_script):
        logger.info("--- [STAGE 1] Standard CVE Enrichment (NVD) ---")
        try:
            subprocess.run([sys.executable, enrich_script] + args, check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run standard CVE enrichment: {e}")
    else:
        logger.warning(f"Standard enrichment script NOT FOUND: {enrich_script}")

    # STAGE 2: NLP ANALYSIS
    if os.path.exists(nlp_script):
        logger.info("--- [STAGE 2] NLP CVE Analysis (spaCy) ---")
        try:
            subprocess.run([sys.executable, nlp_script] + args, check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run NLP CVE analysis: {e}")
    else:
        logger.warning(f"NLP analysis script NOT FOUND: {nlp_script}")

    logger.info("### CONSOLIDATED CVE ENRICHMENT COMPLETED ###")

if __name__ == "__main__":
    run_cve_pipeline()
