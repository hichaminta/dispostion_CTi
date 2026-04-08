import requests
import json
import csv
import os
import io
import sys
import zipfile
import subprocess
import threading
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
load_dotenv(find_dotenv(), override=False)
API_KEY = os.getenv("URLHAUS_API_KEY") or os.getenv("THREATFOX_API_KEY", "")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "urlhaus_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"urlhaus_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# URLhaus JSON exports
URLHAUS_JSON_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
URLHAUS_ONLINE_JSON_URL = "https://urlhaus.abuse.ch/downloads/json/"
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"
BULK_EXPORT_URL_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{api_key}/full.json.zip"

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
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception: pass
    return []

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else DB_FILE
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur sauvegarde JSON ({target_file}) : {e}")

def fetch_json_data(url: str):
    logging.info(f"Fetching: {url}")
    try:
        response = requests.get(url, timeout=300)
        response.raise_for_status()
        content = response.content
        if content.startswith(b'PK\x03\x04'):
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                files = [f for f in z.namelist() if f.endswith('.json')]
                with z.open(files[0]) as f:
                    content = f.read()
        data = json.loads(content)
        if isinstance(data, dict):
            if "urls" in data: return data["urls"]
            results = []
            for k, v in data.items():
                if isinstance(v, list) and len(v) > 0:
                    item = v[0]
                    item["id"] = k
                    results.append(item)
                elif isinstance(v, dict):
                    v["id"] = k
                    results.append(v)
                else:
                    results.append({"id": k})
            return results
        return data if isinstance(data, list) else []
    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
    return []

def fetch_csv_urls():
    logging.info(f"Fetching: {URLHAUS_CSV_URL}")
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=300)
        response.raise_for_status()
        # Le CSV public commence par des commentaires (#)
        lines = response.text.splitlines()
        data_lines = [line for line in lines if line and not line.startswith("#")]
        
        # Mapping CSV -> JSON: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
        reader = csv.DictReader(data_lines, fieldnames=["id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter"])
        results = []
        for row in reader:
            if row["id"] != "id": # Skip headers if any
                # Convert tags string to list
                if row["tags"]:
                    row["tags"] = [t.strip() for t in row["tags"].split(",") if t.strip()]
                else:
                    row["tags"] = []
                results.append(row)
        return results
    except Exception as e:
        logging.error(f"Error fetching CSV: {e}")
    return []

# =========================
# Logique de synchronisation
# =========================

def sync_urlhaus(raw_list, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_raw = len(raw_list)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_raw} items à traiter)...")

    for i, item in enumerate(raw_list, 1):
        scanned_count += 1
        url_id = str(item.get("id"))
        date_added = item.get("date_added") or item.get("dateadded")

        if url_id in existing_ids:
            # Mise à jour des données existantes
            old_item = existing_ids[url_id]
            old_item.update(item)
            old_item["collected_at"] = collected_at
            
            new_records_total.append(old_item)
            added_count += 1
            continue

        if url_id not in existing_ids:
            if total_raw > 1000 and i % 500 == 0:
                print(f"[{i}/{total_raw}] Nouveau URL : {url_id}", end="\r")
                sys.stdout.flush()

            item["id"] = url_id # Harmonisation
            item["collected_at"] = collected_at
            existing_data.append(item)
            existing_ids[url_id] = item
            new_records_total.append(item)
            added_count += 1
            
            # Mise à jour des bornes
            if date_added:
                if not earliest_seen or date_added < earliest_seen:
                    earliest_seen = date_added
                if not latest_seen or date_added > latest_seen:
                    latest_seen = date_added

        if added_count > 0 and added_count % SAVE_EVERY == 0:
            save_json_atomic(existing_data)
            tracking.update({
                "earliest_modified": earliest_seen,
                "latest_modified": latest_seen,
                "last_sync_attempt": datetime.now(timezone.utc).isoformat()
            })
            save_tracking_atomic(tracking)

    if total_raw > 0: print("\n")
    return scanned_count, added_count, earliest_seen, latest_seen

def main():
    if sys.platform == "win32":
        try: sys.stdout.reconfigure(encoding='utf-8')
        except: pass

    # 1. Charger données et indexer
    existing_data = load_existing_data()
    existing_ids = {str(item.get("id")): item for item in existing_data if item.get("id")}
    logging.info(f"Indexation : {len(existing_ids)} items chargés.")

    tracking = load_tracking()
    new_records_total = []

    try:
        # Phase 1 : Récent (30 jours)
        raw_recent = fetch_json_data(URLHAUS_JSON_URL)
        sc1, ad1, e1, l1 = sync_urlhaus(raw_recent, existing_data, existing_ids, tracking, new_records_total, mode="RECENT")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1

        # Phase 2 : Online (Active)
        raw_online = fetch_json_data(URLHAUS_ONLINE_JSON_URL)
        sc2, ad2, e2, l2 = sync_urlhaus(raw_online, existing_data, existing_ids, tracking, new_records_total, mode="ONLINE")
        tracking["earliest_modified"] = e2
        tracking["latest_modified"] = l2

        # Phase 3 : Historique (Full Sync)
        if "--full" in sys.argv:
            # 3a. Tentative Bulk API (Enrichi)
            if API_KEY:
                raw_bulk = fetch_json_data(BULK_EXPORT_URL_TEMPLATE.format(api_key=API_KEY))
                if raw_bulk:
                    sc3, ad3, e3, l3 = sync_urlhaus(raw_bulk, existing_data, existing_ids, tracking, new_records_total, mode="BULK_API")
                    tracking["earliest_modified"] = e3
                    tracking["latest_modified"] = l3
            
            # 3b. Fallback CSV (Complet mais moins enrichi)
            # Idéalement on le fait même si Bulk a réussi pour boucher d'éventuels trous
            raw_csv = fetch_csv_urls()
            if raw_csv:
                sc4, ad4, e4, l4 = sync_urlhaus(raw_csv, existing_data, existing_ids, tracking, new_records_total, mode="CSV_FULL")
                tracking["earliest_modified"] = e4
                tracking["latest_modified"] = l4

    except KeyboardInterrupt:
        logging.warning("Interruption par l'utilisateur.")
    except Exception as e:
        logging.error(f"Erreur durant la synchro : {e}")

    # 4. Finition
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

    # [AUTOMATION] Extraction directe des IOCs/CVEs après collecte
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "urlhaus_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (urlhaus_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    main()
