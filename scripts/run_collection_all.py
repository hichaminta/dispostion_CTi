import os
import subprocess
import sys
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GlobalCollection")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SOURCES_DATA_DIR = os.path.join(PROJECT_ROOT, "Sources_data")


def run_collection():
    if not os.path.exists(SOURCES_DATA_DIR):
        logger.error(f"Sources_data directory not found at {SOURCES_DATA_DIR}")
        return False

    source_folders = sorted([
        f for f in os.listdir(SOURCES_DATA_DIR)
        if os.path.isdir(os.path.join(SOURCES_DATA_DIR, f)) and "alienvault" not in f.lower()
    ])

    logger.info(f"### PLATFORM STATUS: STARTING COLLECTION PIPELINE ###")
    logger.info(f"Found {len(source_folders)} source folders (AlienVault skipped).")

    start_time = time.time()
    success_count = 0
    failed_sources = []

    for folder_name in source_folders:
        source_dir = os.path.join(SOURCES_DATA_DIR, folder_name)
        script_path = os.path.join(source_dir, "script.py")

        if not os.path.exists(script_path):
            logger.warning(f"⚠ No script.py found for source '{folder_name}', skipping.")
            continue

        logger.info(f"── Collecting: {folder_name} ──")
        try:
            result = subprocess.run(
                [sys.executable, script_path],
                cwd=source_dir,  # CWD is the source folder
                check=False
            )
            if result.returncode == 0:
                logger.info(f"✓ {folder_name} collection successful.")
                success_count += 1
            else:
                logger.warning(f"⚠ {folder_name} returned code {result.returncode}.")
                failed_sources.append(folder_name)
        except Exception as e:
            logger.error(f"✗ {folder_name} collection failed with exception: {e}")
            failed_sources.append(folder_name)

    elapsed = time.time() - start_time
    logger.info(f"\n{'='*50}")
    logger.info(f"Global collection completed in {elapsed:.2f}s.")
    logger.info(f"✓ Successful: {success_count}")
    if failed_sources:
        logger.warning(f"✗ Failed: {', '.join(failed_sources)}")
    logger.info(f"{'='*50}")

    return len(failed_sources) == 0


if __name__ == "__main__":
    run_collection()
