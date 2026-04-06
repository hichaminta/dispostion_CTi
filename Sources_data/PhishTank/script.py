import requests
import json
import os
import sys
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
load_dotenv(find_dotenv(), override=False)
API_KEY = os.getenv("PHISHTANK_API_KEY", "")
USER_AGENT = f"phishtank/{API_KEY}" if API_KEY else "phishtank/python-extraction-script"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "phishtank_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"phishtank_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.json"

SAVE_EVERY = 500

# Configuration du logging
import logging
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
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception: pass
    return []

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur sauvegarde JSON ({target_file}) : {e}")

def fetch_phishtank_data():
    logging.info(f"Downloading PhishTank data...")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        response = requests.get(PHISHTANK_URL, headers=headers, timeout=120)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"Error fetching PhishTank: {e}")
        return []

# =========================
# Logique de synchronisation
# =========================

def sync_phishtank(raw_list, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    total_raw = len(raw_list)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_raw} items à traiter)...")

    for i, item in enumerate(raw_list, 1):
        scanned_count += 1
        phish_id = str(item.get("phish_id"))
        sub_time = item.get("submission_time") # "2026-04-06T..."

        if phish_id not in existing_ids:
            print(f"[{i}/{total_raw}] Nouveau phish : {phish_id}", end="\r")
            sys.stdout.flush()

            existing_data.append(item)
            existing_ids.add(phish_id)
            new_records_total.append(item)
            added_count += 1
            
            # Mise à jour des bornes
            if sub_time:
                if not earliest_seen or sub_time < earliest_seen:
                    earliest_seen = sub_time
                if not latest_seen or sub_time > latest_seen:
                    latest_seen = sub_time

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

    # 1. Charger données
    existing_data = load_existing_data()
    existing_ids = {str(item.get("phish_id")) for item in existing_data if item.get("phish_id")}
    logging.info(f"Indexation : {len(existing_ids)} phishings chargés.")

    tracking = load_tracking()

    # 2. Récupérer feed
    raw_list = fetch_phishtank_data()
    if not raw_list:
        logging.warning("Aucune donnée reçue.")
        return

    new_records_total = []

    try:
        # Phase unique (Full Sync du flux JSON)
        sc1, ad1, e1, l1 = sync_phishtank(raw_list, existing_data, existing_ids, tracking, new_records_total, mode="FULL_SYNC")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        logging.info(f"Bilan : {ad1} nouveaux phishings.")

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

if __name__ == "__main__":
    main()
