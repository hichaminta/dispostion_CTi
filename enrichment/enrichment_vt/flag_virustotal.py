"""
flag_virustotal.py
──────────────────
Parcourt tous les fichiers *_enriched.json et pose le flag
  passer_par_virustotal = 1
sur chaque IOC de type url / domain / hash qui possède déjà
des données VirusTotal (vt_malicious_count, malicious_count, vt_tags…).

Ce flag évite de re-scanner ces IOCs lors des prochains runs.
"""

import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FlagVirusTotal")

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR   = os.path.join(BASE_DIR, "output_enrichment")

# Champs qui prouvent qu'un scan VirusTotal a déjà eu lieu
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

# Types d'IOC ciblés (pas les IP — AbuseIPDB gère les IP)
VT_TARGET_TYPES = {"url", "domain", "domaine", "hash", "hashe", "md5", "sha1", "sha256", "sha512"}


def has_vt_data(enrichment: dict) -> bool:
    """Retourne True si l'enrichment contient au moins un champ VT renseigné."""
    for field in VT_INDICATOR_FIELDS:
        val = enrichment.get(field)
        if val is not None and val != "" and val != 0:
            return True
    return False


def run():
    if not os.path.exists(OUTPUT_DIR):
        logger.error(f"Output directory not found: {OUTPUT_DIR}")
        return

    files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")]
    if not files:
        logger.warning("No *_enriched.json files found. Nothing to flag.")
        return

    logger.info(f"[VT Flag] Processing {len(files)} file(s)...")
    total_flagged = 0

    for filename in files:
        filepath = os.path.join(OUTPUT_DIR, filename)
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

                # Déjà flaggué → on passe
                if enrichment.get("passer_par_virustotal") == 1:
                    continue

                # Pose le flag seulement si des données VT existent
                if has_vt_data(enrichment):
                    enrichment["passer_par_virustotal"] = 1
                    modified = True
                    total_flagged += 1
                    logger.debug(f"  [FLAG] {ioc.get('value')} → passer_par_virustotal=1")

        if modified:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=4)
            logger.info(f"  [SAVED] {filename}")

    logger.info(f"[VT Flag] Done — {total_flagged} IOC(s) flagged as passer_par_virustotal=1.")


if __name__ == "__main__":
    run()
