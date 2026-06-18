import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import os
import json
import logging

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("InitNVD")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_FILE = os.path.join(BASE_DIR, "output_cve_ioc", "nvd_extracted.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "nvd_enriched.json")

def initialize_nvd_only():
    if not os.path.exists(INPUT_FILE):
        logger.error(f"Fichier NVD introuvable : {INPUT_FILE}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if isinstance(data, list):
            # Tri par date décroissante (le plus récent en premier)
            data.sort(key=lambda x: x.get("collected_at", ""), reverse=True)
            
            # On ne garde que les 15 plus récents pour l'enrichissement
            limited_data = data[:15]
            
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(limited_data, f, indent=4, ensure_ascii=False)
            
            logger.info(f"[OK] Initialisation spécifique de NVD réussie : {len(limited_data)} records copiés.")
        else:
            logger.error("Le format du fichier nvd_extracted.json n'est pas une liste.")
            
    except Exception as e:
        logger.error(f"[ERREUR] Impossible d'initialiser NVD : {e}")

if __name__ == "__main__":
    initialize_nvd_only()
