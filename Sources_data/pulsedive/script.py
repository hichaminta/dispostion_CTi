import requests
import json
import os
import time
import sys
import subprocess
import threading
import logging
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timezone

# =========================
# Configuration CTI / SOC
# =========================
load_dotenv(find_dotenv())
API_KEY = os.getenv("PULSEDIVE_API_KEY")
BASE_URL = "https://pulsedive.com/api/explore.php"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "pulsedive_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"pulsedive_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")

SAVE_EVERY = 100

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

write_lock = threading.Lock()

# =========================
# Fonctions Utilitaires
# =========================

def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception: pass
    return {}

def save_tracking_atomic(tracking):
    tmp_file = TRACKING_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(tracking, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, TRACKING_FILE)
    except Exception as e:
        logging.error(f"Erreur tracking : {e}")

def load_existing_data():
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception: pass
    return []

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_FILE
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur sauvegarde JSON ({target_file}) : {e}")

def fetch_pulsedive_by_risk(risk, limit=50):
    params = {"limit": limit, "pretty": 1, "key": API_KEY, "q": f"risk={risk}"}
    try:
        response = requests.get(BASE_URL, params=params, timeout=30)
        if response.status_code == 200:
            return response.json().get("results", [])
    except Exception as e:
        logging.error(f"Erreur risk={risk}: {e}")
    return []

# =========================
# Logique de synchronisation
# =========================

def sync_pulsedive(raw_list, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_raw = len(raw_list)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_raw} items à traiter)...")

    for i, item in enumerate(raw_list, 1):
        scanned_count += 1
        indicator = item.get("indicator")
        # Pulsedive stamp_added format: "2026-04-06 10:00:00"
        first_seen = item.get("stamp_added")

        if indicator in existing_ids:
            # Mise à jour des données existantes
            old_item = existing_ids[indicator]
            old_item.update(item)
            old_item["collected_at"] = collected_at
            
            new_records_total.append(old_item)
            added_count += 1
            continue

        if indicator not in existing_ids:
            print(f"[{i}/{total_raw}] Nouveau IOC : {indicator}", end="\r")
            sys.stdout.flush()

            item["collected_at"] = collected_at
            existing_data.append(item)
            existing_ids[indicator] = item
            new_records_total.append(item)
            added_count += 1
            
            # Mise à jour des bornes
            if first_seen:
                if not earliest_seen or first_seen < earliest_seen:
                    earliest_seen = first_seen
                if not latest_seen or first_seen > latest_seen:
                    latest_seen = first_seen

        if added_count > 0 and added_count % SAVE_EVERY == 0:
            save_json_atomic(existing_data)
            tracking.update({
                "earliest_modified": earliest_seen,
                "latest_modified": latest_seen,
                "last_sync_attempt": datetime.now(timezone.utc).isoformat()
            })
            save_tracking_atomic(tracking)

    print("\n")
    return scanned_count, added_count, earliest_seen, latest_seen

def main():
    if sys.platform == "win32":
        try: sys.stdout.reconfigure(encoding='utf-8')
        except: pass

    # 1. Charger données et indexer
    existing_data = load_existing_data()
    existing_ids = {str(item.get("indicator")): item for item in existing_data if item.get("indicator")}
    logging.info(f"Indexation : {len(existing_ids)} items chargés.")

    tracking = load_tracking()
    new_records_total = []

    # 2. Explorer par risque
    risk_levels = ["critical", "high", "medium", "low", "none", "unknown"]
    
    try:
        for risk in risk_levels:
            raw_list = fetch_pulsedive_by_risk(risk)
            if raw_list:
                sc1, ad1, e1, l1 = sync_pulsedive(raw_list, existing_data, existing_ids, tracking, new_records_total, mode=f"RISK_{risk.upper()}")
                tracking["earliest_modified"] = e1
                tracking["latest_modified"] = l1
                time.sleep(1) # Rate limit protection

    except KeyboardInterrupt:
        logging.warning("Interruption.")

    # 3. Finition
    now_iso = datetime.now(timezone.utc).isoformat()
    tracking.update({
        "last_run": now_iso,
        "last_sync_success": now_iso
    })
    save_tracking_atomic(tracking)
    save_json_atomic(existing_data)
    
    if new_records_total:
        logging.info(f"Export journalier : {len(new_records_total)} items")
        save_json_atomic(new_records_total, DAILY_OUTPUT_JSON)

    if os.path.exists(OLD_TRACKING_CSV):
        try: os.remove(OLD_TRACKING_CSV)
        except: pass

    # [AUTOMATION] Extraction directe des IOCs/CVEs après collecte
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "pulsedive_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (pulsedive_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    main()