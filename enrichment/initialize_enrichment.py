import os
import json
import shutil
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("InitializeEnrichment")

# Chemins
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")

def initialize_enrichment_files():
    """
    Copie les fichiers extraits vers le dossier d'enrichissement 
    en les renommant de *_extracted.json vers *_enriched.json.
    """
    if not os.path.exists(INPUT_DIR):
        logger.error(f"Dossier d'entrée introuvable : {INPUT_DIR}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Création du dossier de sortie : {OUTPUT_DIR}")

    files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".json")]
    
    if not files:
        logger.warning(f"Aucun fichier JSON trouvé dans {INPUT_DIR}")
        return

    logger.info(f"Initialisation de l'enrichissement pour {len(files)} fichiers...")

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
                data = json.load(f)
            
            if isinstance(data, list):
                # Sort by collected_at descending (newest first)
                # Handle missing field by using an empty string as fallback
                data.sort(key=lambda x: x.get("collected_at", ""), reverse=True)
                
                # Keep only the 15 most recent
                limited_data = data[:15]
                
                with open(dst_path, "w", encoding="utf-8") as f:
                    json.dump(limited_data, f, indent=4)
                
                logger.info(f"  [OK] {filename} -> {new_filename} (Latest {len(limited_data)} records)")
            else:
                # Fallback: if structure is not a list, copy entire file
                shutil.copy2(src_path, dst_path)
                logger.info(f"  [OK] {filename} -> {new_filename} (Full copy - Non-standard format)")
                
            count += 1
        except Exception as e:
            logger.error(f"  [ERREUR] Impossible d'initialiser {filename} : {e}")

    logger.info(f"Initialisation terminée. {count} fichiers prêts pour l'enrichissement.")

if __name__ == "__main__":
    initialize_enrichment_files()
