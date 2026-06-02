import os
import subprocess
import sys
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GlobalEnrichmentNoClass")

def run_enrichment():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    geo_script = os.path.join(base_dir, "geolocalisation", "enrichir.py")
    urlscan_script = os.path.join(base_dir, "enrichment_url", "enrichir_exclusive_urlscan.py")
    fallback_script = os.path.join(base_dir, "enrichment_url", "enrichir_fallback.py")

    logger.info("### PLATFORM STATUS: INITIALIZING ENRICHMENT FILES ###")
    init_script = os.path.join(base_dir, "initialize_enrichment.py")
    try:
        subprocess.run([sys.executable, init_script], check=False)
    except Exception as e:
        logger.error(f"  [ERROR] Failed to run initialization script: {e}")

    logger.info("### PLATFORM STATUS: STARTING ENRICHMENT PIPELINE (GEO -> URLSCAN -> FALLBACK) ###")

    # ─── STAGE 1: ABUSEIPDB DYNAMIC ENRICHMENT (Local DB + API) ───
    abuseipdb_script = os.path.join(base_dir, "enrichment_ip", "enrichir_abuseipdb.py")
    if os.path.exists(abuseipdb_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 1/5] Dynamic AbuseIPDB Enrichment (Local DB + API)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, abuseipdb_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run AbuseIPDB stage: {e}")
    else:
        logger.warning("[STAGE 1] AbuseIPDB enrichment script NOT FOUND. Skipping.")

    # ─── STAGE 1b: VIRUSTOTAL ENRICHMENT (Local DB + API — URLs / Domains / Hashes / IPs) ───
    vt_script = os.path.join(base_dir, "enrichment_vt", "enrichir_virustotal.py")
    if os.path.exists(vt_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 1b] VirusTotal Enrichment (Local DB first, then API)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, vt_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run VT enrichment stage: {e}")
    else:
        logger.warning("[STAGE 1b] VirusTotal enrichment script NOT FOUND. Skipping.")

    # ─── STAGE 2: GEOLOCATION ───
    if os.path.exists(geo_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 2/5] Geolocation Enrichment...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, geo_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run Stage 2: {e}")
    else:
        logger.warning("[STAGE 2] Geolocation script NOT FOUND. Skipping.")

    # ─── STAGE 3: URLSCAN ANALYSIS (API) ───
    if os.path.exists(urlscan_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 3/5] URLScan.io Deep Analysis...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, urlscan_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run Stage 3: {e}")
    else:
        logger.warning("[STAGE 3] URLScan script NOT FOUND. Skipping.")

    # ─── STAGE 4: FALLBACK ENRICHMENT (Reputation, WHOIS, DNS) ───
    if os.path.exists(fallback_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 4/5] Fallback Enrichment (WHOIS, DNS, Reputation)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, fallback_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run fallback stage: {e}")
    else:
        logger.warning("[STAGE 4] Fallback script NOT FOUND. Skipping.")

    # ─── STAGE 5: CONSOLIDATED CVE ENRICHMENT (NVD + NLP) ───
    cve_consolidated = os.path.join(base_dir, "enrichment_cve", "cve_enrchisment.py")
    if os.path.exists(cve_consolidated):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 5/5] Consolidated CVE Enrichment (NVD & NLP)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, cve_consolidated], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run consolidated CVE stage: {e}")
    else:
        logger.warning("[STAGE 5] Consolidated CVE script NOT FOUND. Skipping.")

    logger.info("==========================================")
    logger.info("ENRICHMENT PIPELINE COMPLETED (Ignored Classification Stage).")
    logger.info("==========================================")

if __name__ == "__main__":
    run_enrichment()
