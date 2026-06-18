import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import shutil
import logging
import subprocess
import sys
from datetime import datetime
try:
    from demo_selective_enrichment import filter_alienvault_for_demo
except ImportError:
    filter_alienvault_for_demo = None

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("InitializeEnrichment")

# Chemins
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
TRACKING_DIR = os.path.join(BASE_DIR, "enrichment", "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "enrichment_initialization.json")

def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {"last_run": None, "sources": {}}

def save_tracking(tracking):
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)
    with open(TRACKING_FILE, "w", encoding="utf-8") as f:
        json.dump(tracking, f, indent=4)

def initialize_enrichment_files(source_filter=None, force=False, demo=False):
    """
    Copie les fichiers extraits vers le dossier d'enrichissement 
    en les renommant de *_extracted.json vers *_enriched.json.
    Utilise un fichier de tracking pour ne mettre à jour que si nécessaire.
    """
    if not os.path.exists(INPUT_DIR):
        logger.error(f"Dossier d'entrée introuvable : {INPUT_DIR}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Création du dossier de sortie : {OUTPUT_DIR}")

    files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".json")]
    
    if source_filter:
        files = [f for f in files if source_filter.lower() in f.lower()]
        logger.info(f"Filtrage pour la source : {source_filter}")
    
    if not files:
        logger.warning(f"Aucun fichier JSON trouvé dans {INPUT_DIR}")
        return

    logger.info(f"Initialisation de l'enrichissement pour {len(files)} fichiers...")
    
    tracking = load_tracking()
    any_updated = False

    count = 0
    for filename in files:
        src_path = os.path.join(INPUT_DIR, filename)

        try:
            with open(src_path, "r", encoding="utf-8") as f:
                new_data = json.load(f)

            if not isinstance(new_data, list):
                dst_path = os.path.join(OUTPUT_DIR, filename.replace(".json", "_enriched.json"))
                shutil.copy2(src_path, dst_path)
                logger.info(f"  [OK] {filename} -> {dst_path} (Full copy - not a list)")
                count += 1
                continue

            # ── Cas spécial DFIR Report : split IOC / VULN ──────────────────
            if "dfir_report" in filename:
                if "vuln" in filename:
                    dst_name = "dfir_report_vuln_enriched.json"
                else:
                    dst_name = "dfir_report_enriched.json"

                # Limite DFIR à 1 seul enregistrement dans le fichier enriched
                # (le plus récent, pour économiser les quotas API d'enrichissement)
                DFIR_MAX_RECORDS = 1

                def _merge_dfir(recs, dst_name, max_records=DFIR_MAX_RECORDS):
                    dst = os.path.join(OUTPUT_DIR, dst_name)
                    # Trier par date descending et garder uniquement les N plus récents
                    recs_sorted = sorted(recs, key=lambda x: x.get("collected_at", ""), reverse=True)
                    recs_limited = recs_sorted[:max_records]

                    existing = []
                    if os.path.exists(dst):
                        try:
                            with open(dst, "r", encoding="utf-8") as f:
                                existing = json.load(f)
                        except Exception:
                            existing = []
                    existing_ids = {r.get("record_id") for r in existing if r.get("record_id")}
                    new_recs = [r for r in recs_limited if r.get("record_id") not in existing_ids]
                    if new_recs or not os.path.exists(dst):
                        # Remplacer entièrement le fichier avec seulement les N records retenus
                        with open(dst, "w", encoding="utf-8") as f:
                            json.dump(recs_limited, f, indent=4)
                        logger.info(f"  [DFIR] {dst_name} {len(recs_limited)} record(s) retenus (max={max_records})")
                    else:
                        logger.info(f"  [DFIR] {dst_name} aucun nouveau record")

                _merge_dfir(new_data, dst_name)

                source_key = filename.replace("_extracted.json", "").replace(".json", "")
                new_data.sort(key=lambda x: x.get("collected_at", ""), reverse=True)
                tracking["sources"][source_key] = new_data[0].get("collected_at", "") if new_data else ""
                any_updated = True
                count += 1
                continue

            # ── Cas général : tous les autres fichiers sources ───────────────
            if "_extracted.json" in filename:
                new_filename = filename.replace("_extracted.json", "_enriched.json")
            else:
                new_filename = filename.replace(".json", "_enriched.json")

            dst_path = os.path.join(OUTPUT_DIR, new_filename)

            existing_data = []
            if os.path.exists(dst_path):
                try:
                    with open(dst_path, "r", encoding="utf-8") as f:
                        existing_data = json.load(f)
                except Exception:
                    existing_data = []

            # ── Séparer les records déjà enrichis des non-enrichis ───────────
            # Un record est "enrichi" s'il contient des données d'enrichissement API
            def _is_enriched(item):
                """Retourne True si le record a déjà été enrichi (données API présentes)."""
                if not isinstance(item, dict):
                    return False
                # Vérifier les IOCs enrichis
                for ioc in item.get("iocs", item.get("indicators", [])):
                    enr = ioc.get("ioc_enrichment", {})
                    if enr and any(enr.get(k) for k in (
                        "abuseipdb", "virustotal", "geography", "country",
                        "url_scan", "passer_par_urlscan", "passer_par_fallback"
                    )):
                        return True
                # Vérifier les CVEs enrichies
                for cve in item.get("cves", []):
                    if cve.get("enrichment"):
                        return True
                # Vérifier un champ enrichment global
                if item.get("enrichment"):
                    return True
                return False

            already_enriched = [item for item in existing_data if _is_enriched(item)]
            not_yet_enriched = [item for item in existing_data if not _is_enriched(item)]

            enriched_keys = {item.get('id') or item.get('value') for item in already_enriched if item}

            # Nouveaux items de l'extraction (pas déjà enrichis)
            truly_new_items = [
                item for item in new_data
                if (item.get('id') or item.get('value')) not in enriched_keys
            ]

            # ── Limites par source ───────────────────────────────────────────
            if "alienvault" in filename.lower():
                # OTX : garder seulement les records ayant AU MOINS 1 IOC (éviter les témoins vides)
                truly_new_items = [
                    item for item in truly_new_items
                    if len(item.get("iocs", item.get("indicators", []))) >= 1
                ]
                # Trier par nombre d'IOCs croissant (moins de trafic API)
                truly_new_items.sort(key=lambda x: len(x.get("iocs", x.get("indicators", []))))
                max_items = 3
            else:
                # Autres sources : 5 records max
                max_items = 5

            # Nouveaux items à injecter (remplacent les anciens non-enrichis)
            items_to_add = truly_new_items[:max_items]

            # ── Stratégie de remplacement ────────────────────────────────────
            # On garde TOUJOURS les records déjà enrichis (données API précieuses)
            # On REMPLACE les anciens non-enrichis par les nouveaux de l'extraction
            if items_to_add:
                replaced = len(not_yet_enriched)
                merged_data = already_enriched + items_to_add
                logger.info(
                    f"  [OK] {filename} -> {new_filename} "
                    f"(+{len(items_to_add)} nouveaux, "
                    f"-{replaced} anciens non-enrichis supprimés, "
                    f"{len(already_enriched)} enrichis conservés, "
                    f"Total: {len(merged_data)})"
                )
            elif already_enriched:
                # Aucun nouveau mais des records enrichis existent → conserver tel quel
                merged_data = already_enriched
                logger.info(
                    f"  [KEEP] {filename} -> {new_filename} "
                    f"(aucun nouveau, {len(already_enriched)} records enrichis conservés)"
                )
            else:
                logger.info(f"  [SKIP] {filename} (aucun nouveau IOC et aucun record enrichi)")
                continue

            new_data.sort(key=lambda x: x.get("collected_at", ""), reverse=True)
            latest_ts  = new_data[0].get("collected_at", "") if new_data else ""
            source_key = filename.replace("_extracted.json", "").replace(".json", "")

            with open(dst_path, "w", encoding="utf-8") as f:
                json.dump(merged_data, f, indent=4)

            tracking["sources"][source_key] = latest_ts
            any_updated = True
            count += 1

        except Exception as e:
            logger.error(f"  [ERREUR] Impossible d'initialiser {filename} : {e}")

    if any_updated:
        tracking["last_run"] = datetime.now().isoformat()
        save_tracking(tracking)

    logger.info(f"Initialisation terminée. {count} fichiers traités.")

    if demo:
        logger.info("Mode DEMO activé : Lancement du filtrage sélectif...")
        if filter_alienvault_for_demo:
            filter_alienvault_for_demo()
        else:
            # Fallback if import failed (e.g. running from different CWD)
            demo_script = os.path.join(os.path.dirname(__file__), "demo_selective_enrichment.py")
            if os.path.exists(demo_script):
                subprocess.run([sys.executable, demo_script], check=False)
            else:
                logger.warning("Script demo_selective_enrichment.py introuvable.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Initialise enrichment files from extraction outputs.")
    parser.add_argument("-s", "--source", help="Only initialize a specific source (e.g. spamhaus)")
    parser.add_argument("-f", "--force", action="store_true", help="Force update even if tracking matches")
    parser.add_argument("-d", "--demo", action="store_true", help="Prepare files for demonstration (keep only most enriched records)")
    args = parser.parse_args()
    
    initialize_enrichment_files(source_filter=args.source, force=args.force, demo=args.demo)
