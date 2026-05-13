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

    # ─── STAGE 1: ABUSEIPDB DYNAMIC ENRICHMENT (Local DB + API) ───
    abuseipdb_script = os.path.join(base_dir, "enrichment_ip", "enrichir_abuseipdb.py")
    if os.path.exists(abuseipdb_script):
        logger.info("──────────────────────────────────────────")
        logger.info("[STAGE 1/7] Dynamic AbuseIPDB Enrichment (Local DB + API)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, abuseipdb_script], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run AbuseIPDB stage: {e}")
    else:
        logger.warning("[STAGE 1] AbuseIPDB enrichment script NOT FOUND. Skipping.")

    # ─── STAGE 1b: VIRUSTOTAL ENRICHMENT (Local DB + API — URLs / Domains / Hashes) ───
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
        logger.info("[STAGE 2/7] Geolocation Enrichment...")
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
        logger.info("[STAGE 3/7] URLScan.io Deep Analysis...")
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
        logger.info("[STAGE 4/7] Fallback Enrichment (WHOIS, DNS, Reputation)...")
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
        logger.info("[STAGE 5/7] Consolidated CVE Enrichment (NVD & NLP)...")
        logger.info("──────────────────────────────────────────")
        try:
            subprocess.run([sys.executable, cve_consolidated], check=False)
        except Exception as e:
            logger.error(f"  [ERROR] Failed to run consolidated CVE stage: {e}")
    else:
        logger.warning("[STAGE 5] Consolidated CVE script NOT FOUND. Skipping.")

    # ─── STAGE 6: CLASSIFICATION & SCORING ─── [DÉSACTIVÉ TEMPORAIREMENT]
    # NOTE: Désactivé en attendant l'analyse de la structure des données enrichies.
    # Réactiver une fois la logique de classification/scoring/confiance définie.
    # classification_script = os.path.join(base_dir, "classification", "enrichir.py")
    # if os.path.exists(classification_script):
    #     logger.info("[STAGE 6/7] Intelligence Classification & Scoring...")
    #     subprocess.run([sys.executable, classification_script, "--skip-enriched"], check=False)
    logger.info("[STAGE 6] Classification SKIPPED (disabled — pending data analysis).")

    # ─── STAGE 7: MITRE ATT&CK MAPPING ─── [DÉSACTIVÉ TEMPORAIREMENT]
    # NOTE: Désactivé en même temps que la Classification.
    # mitre_script = os.path.join(base_dir, "mitre_attack", "mitre_mapper.py")
    # if os.path.exists(mitre_script):
    #     logger.info("[STAGE 7/7] MITRE ATT&CK Mapping...")
    #     subprocess.run([sys.executable, mitre_script, "--skip-mapped"], check=False)
    logger.info("[STAGE 7] MITRE Mapping SKIPPED (disabled — pending data analysis).")

    logger.info("==========================================")
    logger.info("ENRICHMENT PIPELINE COMPLETED.")
    logger.info("==========================================")

if __name__ == "__main__":
    run_enrichment()
