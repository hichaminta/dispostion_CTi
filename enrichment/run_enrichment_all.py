import os
import subprocess
import sys
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GlobalEnrichment")

def run_enrichment():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    geo_script = os.path.join(base_dir, "geolocalisation", "enrichir.py")
    urlscan_script = os.path.join(base_dir, "enrichment_url", "enrichir_exclusive_urlscan.py")
    fallback_script = os.path.join(base_dir, "enrichment_url", "enrichir_fallback.py")

    logger.info("### PLATFORM STATUS: STARTING ENRICHMENT PIPELINE (GEO -> URLSCAN -> FALLBACK) ###")

    # ─── STAGE 1: GEOLOCATION ENRICHMENT ───
    if os.path.exists(geo_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 1/3] Global Geolocation Enrichment (IP -> Country)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, geo_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run geolocation stage: {e}")
    else:
        logger.warning("[STAGE 1] Geolocation script NOT FOUND. Skipping.")

    # ─── STAGE 2: DYNAMIC ANALYSIS (URLScan.io - Exclusive) ───
    if os.path.exists(urlscan_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 2/3] Dynamic URLScan Analysis (Screenshots & Verdicts)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, urlscan_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run URLScan stage: {e}")
    else:
        logger.warning("[STAGE 2] URLScan script NOT FOUND. Skipping.")

    # ─── STAGE 3: FALLBACK ENRICHMENT (Reputation, WHOIS, DNS) ───
    if os.path.exists(fallback_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 3/4] Fallback Enrichment (WHOIS, DNS, Reputation)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, fallback_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run fallback stage: {e}")
    else:
        logger.warning("[STAGE 3] Fallback script NOT FOUND. Skipping.")

    # ─── STAGE 4: CONSOLIDATED CVE ENRICHMENT (NVD + NLP) ───
    cve_consolidated = os.path.join(base_dir, "enrichment_cve", "cve_enrchisment.py")
    if os.path.exists(cve_consolidated):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 4/5] Consolidated CVE Enrichment (NVD & NLP)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, cve_consolidated], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run consolidated CVE stage: {e}")
    else:
        logger.warning("[STAGE 4] Consolidated CVE script NOT FOUND. Skipping.")

    # ─── STAGE 5: VIRUSTOTAL ENRICHMENT (Reputation & Engines) ───
    vt_script = os.path.join(base_dir, "Virus_total_enrchisment", "enrichir_vt.py")
    if os.path.exists(vt_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 6/6] VirusTotal Enrichment (Multi-engine scan)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, vt_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run VirusTotal enrichment stage: {e}")
    else:
        logger.warning("[STAGE 6] VirusTotal enrichment script NOT FOUND. Skipping.")

    logger.info("==========================================")
    logger.info("ENRICHMENT PIPELINE COMPLETED.")
    logger.info("==========================================")

if __name__ == "__main__":
    run_enrichment()
