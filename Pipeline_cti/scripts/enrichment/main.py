import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import logging
from run_enrichment_all import run_enrichment

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')
logger = logging.getLogger("EnrichmentOrchestrator")

if __name__ == "__main__":
    logger.info("Starting enrichment pipeline (GEO -> URLSCAN -> FALLBACK)...")
    run_enrichment()
    logger.info("Enrichment pipeline finished.")
