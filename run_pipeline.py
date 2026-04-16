"""
Master Pipeline Orchestrator
==============================
Usage:
  python run_pipeline.py --step collection
  python run_pipeline.py --step extraction
  python run_pipeline.py --step enrichment
  python run_pipeline.py --step all

Runs the corresponding stage for ALL sources.
"""
import os
import sys
import argparse
import time
import subprocess
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MasterPipeline")

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

STAGES = {
    "collection": os.path.join(PROJECT_ROOT, "scripts", "run_collection_all.py"),
    "extraction": os.path.join(PROJECT_ROOT, "extraction_ioc_cve", "run_extraction_all.py"),
    "enrichment": os.path.join(PROJECT_ROOT, "enrichment", "run_enrichment_all.py"),
}

STAGE_LABELS = {
    "collection": "COLLECTE",
    "extraction": "EXTRACTION IOC/CVE",
    "enrichment": "ENRICHISSEMENT (NLP + GEO)",
}


def run_stage(stage_name: str) -> bool:
    """Runs a single pipeline stage by calling its orchestration script."""
    script_path = STAGES.get(stage_name)

    if not script_path:
        logger.error(f"Unknown stage: '{stage_name}'. Valid stages: {list(STAGES.keys())}")
        return False

    if not os.path.exists(script_path):
        logger.error(f"Stage script not found: {script_path}")
        return False

    label = STAGE_LABELS.get(stage_name, stage_name.upper())
    logger.info(f"\n{'='*60}")
    logger.info(f"  ➤ LANCEMENT : {label}")
    logger.info(f"{'='*60}")

    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=PROJECT_ROOT,
            check=False
        )
        elapsed = time.time() - start
        ok = result.returncode == 0
        icon = "✓" if ok else "✗"
        logger.info(f"{icon} {label} terminé en {elapsed:.2f}s (code: {result.returncode})")
        return ok
    except Exception as e:
        logger.error(f"✗ {label} échoué avec exception : {e}")
        return False


def run_all_stages():
    """Runs all pipeline stages sequentially."""
    total_start = time.time()
    results = {}

    logger.info("\n" + "="*60)
    logger.info("  *** MASTER CTI PIPELINE - EXECUTION COMPLETE ***")
    logger.info("="*60)

    for stage in ["collection", "extraction", "enrichment"]:
        ok = run_stage(stage)
        results[stage] = ok
        if not ok:
            logger.warning(f"⚠ L'étape '{stage}' a échoué mais le pipeline continue...")

    total_elapsed = time.time() - total_start
    logger.info("\n" + "="*60)
    logger.info("  RÉSUMÉ DU PIPELINE")
    logger.info("="*60)
    for stage, ok in results.items():
        icon = "✓" if ok else "✗"
        logger.info(f"  {icon}  {STAGE_LABELS[stage]}")
    logger.info(f"\n  Durée totale : {total_elapsed:.2f}s")
    logger.info("="*60 + "\n")

    return all(results.values())


def main():
    parser = argparse.ArgumentParser(
        description="Master CTI Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Étapes disponibles:
  collection  -> Telecharge les donnees brutes de toutes les sources
  extraction  -> Extrait les IOCs et CVEs des donnees collectees
  enrichment  -> Enrichit les IOCs (NLP + Geolocalisation)
  all         -> Lance toutes les etapes dans l'ordre

Exemples:
  python run_pipeline.py --step collection
  python run_pipeline.py --step all
        """
    )
    parser.add_argument(
        "--step",
        choices=["collection", "extraction", "enrichment", "all"],
        required=True,
        help="Étape du pipeline à exécuter."
    )

    args = parser.parse_args()

    if args.step == "all":
        success = run_all_stages()
    else:
        success = run_stage(args.step)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
