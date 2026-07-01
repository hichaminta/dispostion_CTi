import sys
import os
import subprocess
import time
import logging

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s', encoding='utf-8')
logger = logging.getLogger("CTI_Master_Pipeline")

# Définition des chemins absolus
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Liste des étapes du pipeline avec leur chemin et dossier de travail
PIPELINE_STEPS = [
    {
        "name": "Collection des données",
        "script": os.path.join(os.path.dirname(__file__), "collection", "run_collection_all.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "collection")
    },
    {
        "name": "Extraction des IOCs et CVEs",
        "script": os.path.join(os.path.dirname(__file__), "extraction_ioc_cve", "run_extraction_all.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "extraction_ioc_cve")
    },
    {
        "name": "Enrichissement global",
        "script": os.path.join(os.path.dirname(__file__), "enrichment", "run_enrichment_all.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "enrichment")
    },
    {
        "name": "Corrélation pré-MISP",
        "script": os.path.join(os.path.dirname(__file__), "misp_integration", "correlation_pre_misp.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "misp_integration")
    },
    {
        "name": "Export STIX 2.1",
        "script": os.path.join(os.path.dirname(__file__), "misp_integration", "stix_exporter.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "misp_integration")
    },
    {
        "name": "Intégration MISP API",
        "script": os.path.join(os.path.dirname(__file__), "misp_integration", "misp_api_integration.py"),
        "cwd": os.path.join(os.path.dirname(__file__), "misp_integration")
    }
]

def run_pipeline():
    logger.info("==========================================")
    logger.info("DÉMARRAGE DU PIPELINE CTI GLOBAL")
    logger.info("==========================================")
    
    total_start_time = time.time()
    
    for step_num, step in enumerate(PIPELINE_STEPS, 1):
        step_name = step["name"]
        script_path = step["script"]
        cwd = step["cwd"]
        
        logger.info(f"\n[{step_num}/{len(PIPELINE_STEPS)}] Début de l'étape : {step_name}")
        
        if not os.path.exists(script_path):
            logger.error(f"[ERREUR] Le script n'existe pas : {script_path}")
            logger.error("Arrêt du pipeline.")
            sys.exit(1)
            
        step_start_time = time.time()
        try:
            # Exécution du script
            cmd = [sys.executable, script_path] + sys.argv[1:]
            result = subprocess.run(cmd, check=True, cwd=cwd)
            
            step_duration = time.time() - step_start_time
            logger.info(f"[{step_num}/{len(PIPELINE_STEPS)}] ✔️ Étape terminée avec succès ({step_duration:.2f} s).")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"[ERREUR] L'étape '{step_name}' a échoué avec le code de retour {e.returncode}.")
            logger.error("Arrêt du pipeline pour éviter des incohérences.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"[ERREUR INATTENDUE] lors de l'étape '{step_name}': {e}")
            sys.exit(1)
            
    total_duration = time.time() - total_start_time
    logger.info("==========================================")
    logger.info(f"PIPELINE CTI TERMINÉ AVEC SUCCÈS")
    logger.info(f"Durée totale : {total_duration:.2f} secondes.")
    logger.info("==========================================")

if __name__ == "__main__":
    run_pipeline()
