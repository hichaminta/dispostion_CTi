import os
import json
import logging
import requests
import sys
import threading
from datetime import datetime, timezone

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "openphish_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"openphish_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
FEED_URL = "https://openphish.com/feed.txt"

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
        except Exception as e:
            logging.warning(f"Impossible de lire le tracking JSON : {e}")
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
        except Exception:
            pass
    return []

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

def fetch_openphish_feed():
    response = requests.get(FEED_URL, timeout=30)
    response.raise_for_status()
    return [line.strip() for line in response.text.splitlines() if line.strip()]

# =========================
# Logique de synchronisation
# =========================

def sync_openphish(urls, existing_data, existing_urls, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_urls = len(urls)

    logging.info(f"Démarrage synchronisation [{mode}] ({total_urls} URLs à traiter)...")

    for i, url in enumerate(urls, 1):
        scanned_count += 1
        
        if url not in existing_urls:
            print(f"[{i}/{total_urls}] Nouveau phishing : {url[:50]}...", end="\r")
            sys.stdout.flush()

            record = {
                "source": "openphish",
                "url": url,
                "collected_at": collected_at
            }
            existing_data.append(record)
            existing_urls.add(url)
            new_records_total.append(record)
            added_count += 1
            
            # Mise à jour des bornes
            if not earliest_seen or collected_at < earliest_seen:
                earliest_seen = collected_at
            if not latest_seen or collected_at > latest_seen:
                latest_seen = collected_at

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
    existing_urls = {item.get("url") for item in existing_data if item.get("url")}
    logging.info(f"Indexation : {len(existing_urls)} URLs chargées.")

    tracking = load_tracking()

    # 2. Récupérer feed
    try:
        urls = fetch_openphish_feed()
        logging.info(f"{len(urls)} URLs récupérées d'OpenPhish.")
    except Exception as e:
        logging.error(f"Erreur téléchargement : {e}")
        return

    new_records_total = []

    try:
        # Phase unique pour OpenPhish (Full Sync du feed actuel)
        sc_1, ad_1, e1, l1 = sync_openphish(urls, existing_data, existing_urls, tracking, new_records_total, mode="FULL_SYNC")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        logging.info(f"Bilan : {ad_1} nouvelles URLs.")

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

