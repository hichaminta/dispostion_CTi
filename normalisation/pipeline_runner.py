import subprocess
import sys
import argparse
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PipelineRunner")

def run_command(command):
    logger.info(f"Exécution de : {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de {' '.join(command)}")
        logger.error(e.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description="Run the CTI pipeline (Standardize -> Normalize)")
    parser.add_argument("-s", "--source", help="Source to process (default: all)")
    args = parser.parse_args()

    source = args.source
    source_display = source.upper() if source else "ALL SOURCES"
    logger.info(f"--- DÉBUT DE LA PIPELINE POUR : {source_display} ---")

    source_flag = ["-s", source] if source else []

    # Étape 1 : Standardization
    logger.info(f"Étape 1 : Standardisation des données enrichies ({source_display})...")
    if not run_command([sys.executable, "normalisation/standardize.py"] + source_flag):
        logger.error("La standardisation a échoué. Arrêt de la pipeline.")
        sys.exit(1)

    # Étape 2 : MISP Normalization
    logger.info(f"Étape 2 : Normalisation MISP ({source_display})...")
    if not run_command([sys.executable, "normalisation/misp_normalizer.py"] + source_flag):
        logger.error("La normalisation MISP a échoué. Arrêt de la pipeline.")
        sys.exit(1)

    logger.info(f"--- PIPELINE TERMINÉE AVEC SUCCÈS POUR {source_display} ---")
    logger.info("Note : L'intégration MISP n'a pas été lancée comme demandé.")

if __name__ == "__main__":
    main()
