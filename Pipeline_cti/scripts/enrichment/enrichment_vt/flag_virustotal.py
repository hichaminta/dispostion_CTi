import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
"""
flag_virustotal.py
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Parcourt tous les fichiers *_enriched.json et pose le flag
  passer_par_virustotal = 1
sur chaque IOC de type url / domain / hash qui possÃ¨de dÃ©jÃ 
des donnÃ©es VirusTotal (vt_malicious_count, malicious_count, vt_tagsâ€¦).

Ce flag Ã©vite de re-scanner ces IOCs lors des prochains runs.
"""

import os
import json
import logging

logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FlagVirusTotal")

BASE_DIR           = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources")

# Champs qui prouvent qu'un scan VirusTotal a dÃ©jÃ  eu lieu
VT_INDICATOR_FIELDS = [
    "vt_malicious_count",
    "malicious_count",
    "vt_total_engines",
    "vt_tags",
    "vt_score",
    "vt_verdict",
    "vt_permalink",
    "vt_last_analysis_date",
]

# Types d'IOC ciblÃ©s (pas les IP â€” AbuseIPDB gÃ¨re les IP)
VT_TARGET_TYPES = {"url", "domain", "domaine", "hash", "hashe", "md5", "sha1", "sha256", "sha512"}


def has_vt_data(enrichment: dict) -> bool:
    """Retourne True si l'enrichment contient au moins un champ VT renseignÃ©."""
    for field in VT_INDICATOR_FIELDS:
        val = enrichment.get(field)
        if val is not None and val != "" and val != 0:
            return True
    return False


def run():
    import glob
    pattern = os.path.join(GLOBAL_SOURCES_DIR, "*", "enrichment", "*_enriched.json")
    all_files = glob.glob(pattern)
    if not all_files:
        logger.warning("No *_enriched.json files found. Nothing to flag.")
        return

    logger.info(f"[VT Flag] Processing {len(all_files)} file(s)...")
    total_flagged = 0

    for filepath in all_files:
        filename = os.path.basename(filepath)
        modified = False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception as e:
            logger.error(f"Cannot read {filename}: {e}")
            continue

        for record in records:
            for ioc in record.get("iocs", []):
                ioc_type = ioc.get("type", "").lower()
                if ioc_type not in VT_TARGET_TYPES:
                    continue

                enrichment = ioc.setdefault("ioc_enrichment", {})

                # DÃ©jÃ  flagguÃ© â†’ on passe
                if enrichment.get("passer_par_virustotal") == 1:
                    continue

                # Pose le flag seulement si des donnÃ©es VT existent
                if has_vt_data(enrichment):
                    enrichment["passer_par_virustotal"] = 1
                    modified = True
                    total_flagged += 1
                    logger.debug(f"  [FLAG] {ioc.get('value')} â†’ passer_par_virustotal=1")

        if modified:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=4)
            logger.info(f"  [SAVED] {filename}")

    logger.info(f"[VT Flag] Done â€” {total_flagged} IOC(s) flagged as passer_par_virustotal=1.")


if __name__ == "__main__":
    run()
