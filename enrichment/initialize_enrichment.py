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
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
        # Déterminer le nouveau nom
        if "_extracted.json" in filename:
            new_filename = filename.replace("_extracted.json", "_enriched.json")
        else:
            new_filename = filename.replace(".json", "_enriched.json")
            
        src_path = os.path.join(INPUT_DIR, filename)
        dst_path = os.path.join(OUTPUT_DIR, new_filename)

        try:
            with open(src_path, "r", encoding="utf-8") as f:
                new_data = json.load(f)
            
            if isinstance(new_data, list):
                # 1. Load existing data if it exists
                existing_data = []
                if os.path.exists(dst_path):
                    try:
                        with open(dst_path, "r", encoding="utf-8") as f:
                            existing_data = json.load(f)
                    except:
                        existing_data = []
                
                # 2. Identify new items (not in existing_data)
                # We use 'id' or 'value' as unique identifier
                existing_keys = {item.get('id') or item.get('value') for item in existing_data if item}
                truly_new_items = [item for item in new_data if (item.get('id') or item.get('value')) not in existing_keys]
                
                # 3. Limit the addition to 15 items
                items_to_add = truly_new_items[:15]
                
                if not items_to_add:
                    logger.info(f"  [SKIP] {filename} (Aucun nouvel IOC trouvé)")
                    continue
                
                # 4. Merge
                # We put new items at the beginning (most recent)
                merged_data = items_to_add + existing_data
                
                # Get the latest collected_at date for tracking from the new data
                # Sort new data by collected_at descending
                new_data.sort(key=lambda x: x.get("collected_at", ""), reverse=True)
                latest_ts = new_data[0].get("collected_at", "") if new_data else ""
                source_key = filename.replace("_extracted.json", "").replace(".json", "")
                
                # Save merged data
                with open(dst_path, "w", encoding="utf-8") as f:
                    json.dump(merged_data, f, indent=4)
                
                # Update tracking info
                tracking["sources"][source_key] = latest_ts
                any_updated = True
                
                logger.info(f"  [OK] {filename} -> {new_filename} (+{len(items_to_add)} nouveaux IOCs, Total: {len(merged_data)})")
            else:
                shutil.copy2(src_path, dst_path)
                logger.info(f"  [OK] {filename} -> {new_filename} (Full copy - not a list)")
                
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
