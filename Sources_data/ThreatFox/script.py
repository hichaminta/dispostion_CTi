import requests
import json
import os
import sys
import io
import zipfile
import threading
import logging
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
load_dotenv(find_dotenv(), override=False)
API_KEY = os.getenv("THREATFOX_API_KEY", "")
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
BULK_EXPORT_URL_TEMPLATE = "https://threatfox-api.abuse.ch/v2/files/exports/{api_key}/full.json.zip"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "threatfox_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"threatfox_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

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

def fetch_iocs(days: int) -> list:
    payload = {"query": "get_iocs", "days": days}
    headers = {"Content-Type": "application/json"}
    if API_KEY: headers["Auth-Key"] = API_KEY
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        if result.get("query_status") == "ok":
            return result.get("data", [])
    except Exception as e:
        logging.error(f"API Error: {e}")
    return []

def fetch_bulk_iocs() -> list:
    if not API_KEY: return []
    url = BULK_EXPORT_URL_TEMPLATE.format(api_key=API_KEY)
    logging.info("Downloading bulk export...")
    try:
        response = requests.get(url, timeout=300)
        response.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            json_filename = [f for f in z.namelist() if f.endswith('.json')][0]
            with z.open(json_filename) as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # ThreatFox bulk v2 is {id: {data}} OR {id: [{data}]}
                    flattened = []
                    for ioc_id, items in data.items():
                        if isinstance(items, list):
                            for it in items:
                                if "id" not in it: it["id"] = ioc_id
                                flattened.append(it)
                        else:
                            if "id" not in items: items["id"] = ioc_id
                            flattened.append(items)
                    return flattened
                return data if isinstance(data, list) else []
    except Exception as e:
        logging.error(f"Bulk Error: {e}")
    return []

# =========================
# Logique de synchronisation
# =========================

def sync_threatfox(raw_list, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_raw = len(raw_list)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_raw} items à traiter)...")

    for i, item in enumerate(raw_list, 1):
        scanned_count += 1
        ioc_id = item.get("id")
        first_seen = item.get("first_seen") # "2026-04-06 10:00:00"

        if ioc_id not in existing_ids:
            print(f"[{i}/{total_raw}] Nouveau IOC : {ioc_id}", end="\r")
            sys.stdout.flush()

            item["collected_at"] = collected_at
            existing_data.append(item)
            existing_ids.add(ioc_id)
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

    # 1. Charger données
    existing_data = load_existing_data()
    existing_ids = {str(item.get("id")) for item in existing_data if item.get("id")}
    logging.info(f"Indexation : {len(existing_ids)} IOCs chargés.")

    tracking = load_tracking()
    new_records_total = []

    try:
        # Phase 1 : Nouveautés (Recent 7 days max for API)
        raw_recent = fetch_iocs(days=7)
        sc1, ad1, e1, l1 = sync_threatfox(raw_recent, existing_data, existing_ids, tracking, new_records_total, mode="AFTER")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        
        # Phase 2 : Historique (si --full)
        if "--full" in sys.argv:
            raw_bulk = fetch_bulk_iocs()
            if raw_bulk:
                sc2, ad2, e2, l2 = sync_threatfox(raw_bulk, existing_data, existing_ids, tracking, new_records_total, mode="BEFORE")
                tracking["earliest_modified"] = e2
                tracking["latest_modified"] = l2

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

