import os
import json
import logging
import requests
import sys
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "openphish_data.json")
# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"openphish_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

FEED_URL = "https://openphish.com/feed.txt"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ── Helpers ────────────────────────────────────────────────────────────────────
def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()

def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Impossible de lire le tracking JSON : {e}")
    
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            import csv
            with open(OLD_TRACKING_FILE, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
                if len(rows) > 1 and rows[1]:
                    return {"last_sync_success": rows[1][0]}
        except:
            pass
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
    urls = []
    for line in response.text.splitlines():
        url = line.strip()
        if url:
            urls.append(url)
    return urls

def main():
    # Fix Windows encoding issues for arrow characters
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    try:
        logging.info("Chargement des données existantes...")
        existing_data = load_existing_data()
        existing_urls = { item.get("url") for item in existing_data if item.get("url") }
        
        tracking = load_tracking()
        tracking["last_sync_attempt"] = now_utc_iso()

        last_run = tracking.get("last_run", tracking.get("last_sync_success"))
        if last_run:
            logging.info(f"Dernière extraction : {last_run}")

        logging.info(f"Téléchargement du feed depuis {FEED_URL}...")
        try:
            raw_urls = fetch_openphish_feed()
            logging.info(f"{len(raw_urls)} URL(s) récupérées.")
        except Exception as e:
            logging.error(f"Erreur de téléchargement : {e}")
            return

        collected_time = now_utc_iso()
        new_items = []
        total_urls = len(raw_urls)
        print(f"  → Filtrage de {total_urls} URLs...")
        
        for i, url in enumerate(raw_urls, 1):
            print(f"[{i}/{total_urls}] Vérification : {url[:70]}...", end="\r")
            sys.stdout.flush()
            if url not in existing_urls:
                new_items.append({
                    "source": "openphish",
                    "url": url,
                    "first_seen": None,
                    "collected_at": collected_time
                })

        print("\n" + "="*50)
        if new_items:
            logging.info(f"{len(new_items)} nouvelle(s) URL(s) trouvée(s).")
            print("\nNouvelles URLs OpenPhish ajoutées :")
            display_limit = 20
            for item in new_items[:display_limit]:
                print(f" [+] {item['url']}")
            if len(new_items) > display_limit:
                print(f" ... et {len(new_items) - display_limit} autres.")
                
            updated_data = existing_data + new_items
            save_json_atomic(updated_data)
            
            # Save daily export
            logging.info(f"Sauvegarde des {len(new_items)} nouvelles URL(s) dans {DAILY_OUTPUT_JSON}")
            save_json_atomic(new_items, DAILY_OUTPUT_JSON)
        else:
            logging.info("Aucune nouvelle URL trouvée.")
            updated_data = existing_data
        print("="*50)

        # Calcul des dates min/max pour le tracking
        if updated_data:
            dates = [item.get("collected_at") for item in updated_data if item.get("collected_at")]
            if dates:
                tracking["earliest_modified"] = min(dates)
                tracking["latest_modified"] = max(dates)

        tracking["last_run"] = now_utc_iso()
        tracking["last_sync_success"] = tracking["last_run"]
        save_tracking_atomic(tracking)

    except Exception as e:
        logging.error(f"Erreur fatale : {e}")

    if os.path.exists(OLD_TRACKING_FILE):
        try:
            os.remove(OLD_TRACKING_FILE)
            logging.info(f"Ancien fichier de tracking supprimé : {OLD_TRACKING_FILE}")
        except:
            pass

if __name__ == "__main__":
    main()
