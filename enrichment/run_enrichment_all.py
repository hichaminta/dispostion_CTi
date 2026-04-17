import os
import subprocess
import sys
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GlobalEnrichment")

# Pipeline Configuration
SKIP_SOURCES = {"alienvault"}

def run_enrichment():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    nlp_scripts_dir = os.path.join(base_dir, "nlp", "scripts")
    geo_script = os.path.join(base_dir, "geolocalisation", "enrichir.py")
    urlscan_script = os.path.join(base_dir, "urlscan_enrichment", "enrichir_exclusive_urlscan.py")

    logger.info("### PLATFORM STATUS: STARTING FULL ENRICHMENT PIPELINE (NLP -> GEO -> SCAN) ###")

    # ─── STAGE 1: NLP ENRICHMENT ───
    if os.path.exists(nlp_scripts_dir):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 1/3] NLP Enrichment (Entities, Categories, Families)...")
        logger.info("──────────────────────────────────────────")
        for script_name in sorted(os.listdir(nlp_scripts_dir)):
            if not script_name.endswith('_enricher.py'): continue
            if any(skip in script_name.lower() for skip in SKIP_SOURCES): continue

            script_path = os.path.join(nlp_scripts_dir, script_name)
            logger.info(f"  [NLP] Processing {script_name}...")
            try:
                subprocess.run([sys.executable, script_path], check=False)
            except Exception as e:
                logger.error(f"  [ERROR] Failed to run {script_name}: {e}")
    else:
        logger.warning("[STAGE 1] NLP folder NOT FOUND. Skipping.")

    # ─── STAGE 2: GEOLOCATION ENRICHMENT ───
    if os.path.exists(geo_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 2/3] Global Geolocation Enrichment (IP -> Country)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, geo_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run geolocation stage: {e}")
    else:
        logger.warning("[STAGE 2] Geolocation script NOT FOUND. Skipping.")

    # ─── STAGE 3: DYNAMIC ANALYSIS (URLScan.io - Exclusive) ───
    if os.path.exists(urlscan_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 3/3] Dynamic URLScan Analysis (Screenshots & Verdicts)...")
        logger.info("──────────────────────────────────────────")
        try:
            # Explicitly processing for all files (Unified) when called from here
            subprocess.run([sys.executable, urlscan_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run URLScan stage: {e}")
    else:
        logger.warning("[STAGE 3] URLScan script NOT FOUND. Skipping.")

    logger.info("==========================================")
    logger.info("FULL ENRICHMENT PIPELINE COMPLETED.")
    logger.info("==========================================")

if __name__ == "__main__":
    run_enrichment()
