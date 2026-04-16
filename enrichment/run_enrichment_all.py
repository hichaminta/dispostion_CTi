import os
import subprocess
import sys
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GlobalEnrichment")

# ─────────────────────────────────────────────────────────────────────────────
# Sources classification:
#
#  NLP_SOURCES   = Sources with narrative text → NLP extracts malware families,
#                  threat categories, locations, CVEs from free text.
#
#  NO_NLP_SOURCES = Sources with structured data only → no text to analyze.
#                   Characteristics come from structured fields (score, country, isp...).
#                   NLP is skipped for these → saves significant processing time.
# ─────────────────────────────────────────────────────────────────────────────

NLP_SOURCES = {
    "virustotal",     # Engine analysis, detection names, campaign descriptions
    "threatfox",      # Malware family tags + short context
    "malwarebazaar",  # Malware name, signature, family in description
    "pulsedive",      # Threat context and campaign descriptions
}

# Skip list (Sources that are too slow or redundant)
SKIP_SOURCES = {
    "alienvault",  # Completely skipped as requested (takes too much time)
}

def run_enrichment():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    nlp_scripts_dir = os.path.join(base_dir, "nlp", "scripts")
    geo_script = os.path.join(base_dir, "geolocalisation", "enrichir.py")

    if not os.path.exists(nlp_scripts_dir):
        logger.error(f"NLP scripts directory not found at {nlp_scripts_dir}")
        return

    logger.info("### PLATFORM STATUS: STARTING ENRICHMENT PIPELINE ###")
    logger.info(f"  Permanent Skip   : {', '.join(sorted(SKIP_SOURCES))}")
    logger.info(f"  Light NLP mode enabled for technical sources.")

    # ─── STAGE 1: NLP ENRICHMENT ───
    logger.info("STAGE 1: NLP Enrichment (Entities, Categories, Families)...")

    for script_name in sorted(os.listdir(nlp_scripts_dir)):
        if not script_name.endswith('_enricher.py'):
            continue

        # Derive the source ID from the filename
        raw_id = script_name.replace("_enricher.py", "").lower()

        # Check if this source should be skipped
        if any(skip in raw_id for skip in SKIP_SOURCES):
            logger.info(f"  [SKIP] {script_name} — manually disabled.")
            continue

        script_path = os.path.join(nlp_scripts_dir, script_name)
        logger.info(f"  [NLP] Processing {script_name}...")
        try:
            # Use subprocess to run each maintainable enricher
            subprocess.run([sys.executable, script_path], check=False)
        except Exception as e:
            logger.error(f"Failed to run {script_name}: {e}")

    # ─── STAGE 2: GEOLOCATION ENRICHMENT (All sources — Unified) ───
    if os.path.exists(geo_script):
        logger.info("STAGE 2: Global Geolocation Enrichment (All sources, Local DB + API)...")
        try:
            subprocess.run([sys.executable, geo_script], check=False)
        except Exception as e:
            logger.error(f"Failed to run geolocation stage: {e}")
    else:
        logger.warning(f"Stage 2 script (enrichir.py) not found at {geo_script}.")

    logger.info("Global enrichment pipeline completed.")


if __name__ == "__main__":
    run_enrichment()
