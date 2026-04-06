import os
import json
import ipaddress
import logging
import sys
import threading
from datetime import datetime, timezone
import requests

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "feodotracker_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"feodotracker_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

SAVE_EVERY = 500

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

def fetch_feodo_feed():
    headers = {"User-Agent": "Mozilla/5.0"}
    r = requests.get(FEODO_URL, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

# =========================
# Logique de synchronisation
# =========================

def sync_feodotracker(raw_list, existing_data, existing_keys, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_raw = len(raw_list)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_raw} items à traiter)...")

    for i, row in enumerate(raw_list, 1):
        scanned_count += 1
        dst_ip = str(row.get("ip_address", "")).strip()
        malware = str(row.get("malware", "")).strip()
        first_seen = row.get("first_seen") # "2026-04-06 ..."

        key = (dst_ip, malware)
        if key not in existing_keys:
            print(f"[{i}/{total_raw}] Nouveau C2 : {dst_ip} ({malware})", end="\r")
            sys.stdout.flush()

            row["collected_at"] = collected_at
            existing_data.append(row)
            existing_keys.add(key)
            new_records_total.append(row)
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

    # 1. Charger données
    existing_data = load_existing_data()
    existing_keys = {(str(item.get("ip_address")), str(item.get("malware"))) for item in existing_data if item.get("ip_address")}
    logging.info(f"Indexation : {len(existing_keys)} items chargés.")

    tracking = load_tracking()
    new_records_total = []

    # 2. Récupérer feed
    try:
        raw_list = fetch_feodo_feed()
        if not isinstance(raw_list, list): raw_list = []
        logging.info(f"{len(raw_list)} items récupérés de FeodoTracker.")
    except Exception as e:
        logging.error(f"Erreur téléchargement : {e}")
        return

    try:
        # Phase unique (Full Sync du feed JSON)
        sc1, ad1, e1, l1 = sync_feodotracker(raw_list, existing_data, existing_keys, tracking, new_records_total, mode="FULL_SYNC")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        logging.info(f"Bilan : {ad1} nouveaux IOCs.")

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

    if os.path.exists(OLD_TRACK_FILE := os.path.join(SCRIPT_DIR, "last_run.csv")):
        os.remove(OLD_TRACK_FILE)

if __name__ == "__main__":
    main()

()