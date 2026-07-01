import os
import sys
import subprocess
import time
import logging

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger("CollectionRunner")

def run_all_collections():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Trouver tous les sous-dossiers contenant un script.py
    collection_scripts = []
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        if os.path.isdir(item_path):
            script_path = os.path.join(item_path, "script.py")
            if os.path.exists(script_path):
                collection_scripts.append((item, script_path))
                
    collection_scripts.sort() # Optionnel, pour un ordre déterministe
    
    logger.info(f"Début de la collection globale pour {len(collection_scripts)} sources...")
    start_time = time.time()
    
    for source_name, script_path in collection_scripts:
        logger.info(f"──────────────────────────────────────────")
        logger.info(f"--- Lancement de la collection : {source_name} ---")
        try:
            cmd = [sys.executable, script_path] + sys.argv[1:]
            subprocess.run(cmd, check=True, cwd=os.path.dirname(script_path))
        except subprocess.CalledProcessError as e:
            logger.error(f"[ERREUR] Échec de la collection pour {source_name} (Code: {e.returncode})")
        except Exception as e:
            logger.error(f"[ERREUR] Erreur inattendue pour {source_name}: {e}")
            
    end_time = time.time()
    logger.info(f"──────────────────────────────────────────")
    logger.info(f"Toutes les collections ont été terminées en {end_time - start_time:.2f} secondes.")

if __name__ == "__main__":
    run_all_collections()
