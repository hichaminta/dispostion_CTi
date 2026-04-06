import os
import json
import ipaddress
import logging
from datetime import datetime, timezone

import requests

# =========================================================
# CONFIG
# =========================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "feodotracker_data.json")
# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"feodotracker_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CTI-Collector/1.0)"
}
TIMEOUT = 30

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# =========================================================
# UTILS
# =========================================================
def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

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

# =========================================================
# DOWNLOAD
# =========================================================
def download_feed():
    logging.info(f"Download: {FEODO_URL}")
    r = requests.get(FEODO_URL, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text

# =========================================================
# PARSE JSON
# =========================================================
def parse_feodo_json(raw_text):
    data = json.loads(raw_text)
    items = []

    if not isinstance(data, list):
        return items

    collected_at = utc_now_iso()
    for idx, row in enumerate(data, start=1):
        dst_ip = (row.get("ip_address") or "").strip()
        if not dst_ip or not is_valid_ip(dst_ip):
            continue

        ip_obj = ipaddress.ip_address(dst_ip)
        item = {
            "source": "feodotracker",
            "source_provider": "abuse.ch",
            "feed_name": "ipblocklist",
            "ioc_type": "ip",
            "ioc_value": dst_ip,
            "ip_version": ip_obj.version,
            "port": row.get("port"),
            "c2_status": (row.get("status") or "").strip(),
            "malware_family": (row.get("malware") or "").strip(),
            "hostname": (row.get("hostname") or "").strip() or None,
            "as_number": row.get("as_number"),
            "as_name": (row.get("as_name") or "").strip() or None,
            "country": (row.get("country") or "").strip() or None,
            "first_seen_utc": (row.get("first_seen") or "").strip() or None,
            "last_online": (row.get("last_online") or "").strip() or None,
            "source_url": FEODO_URL,
            "collected_at": collected_at
        }
        items.append(item)
    return items

def main():
    try:
        tracking = load_tracking()
        tracking["last_sync_attempt"] = utc_now_iso()
        
        last_run = tracking.get("last_run", tracking.get("last_sync_success"))
        if last_run:
            logging.info(f"Dernière exécution : {last_run}")

        raw_text = download_feed()
        new_items = parse_feodo_json(raw_text)
        
        existing_data = load_existing_data()
        # Clé de déduplication : ioc_value + malware_family
        existing_keys = { (item["ioc_value"], item["malware_family"]) for item in existing_data }
        
        to_add = []
        total_new = len(new_items)
        if total_new > 0:
            logging.info(f"Vérification de {total_new} nouveaux items potentiels...")
            
        for i, item in enumerate(new_items, 1):
            key = (item["ioc_value"], item["malware_family"])
            print(f"[{i}/{total_new}] Vérification : {item['ioc_value']}", end="\r")
            import sys
            sys.stdout.flush()
            if key not in existing_keys:
                to_add.append(item)
        
        print("\n" + "="*50)
        if to_add:
            logging.info(f"{len(to_add)} nouveaux IOCs ajoutés.")
            print("\nNouveaux IOC ajoutés :")
            # Limite d'affichage à 20
            display_limit = 20
            for item in to_add[:display_limit]:
                print(f" [+] {item['ioc_value']} ({item['malware_family']})")
            if len(to_add) > display_limit:
                print(f" ... et {len(to_add) - display_limit} autres.")
                
            updated_data = existing_data + to_add
            save_json_atomic(updated_data)
            
            # Save daily export
            logging.info(f"Sauvegarde des {len(to_add)} nouveaux IOCs dans {DAILY_OUTPUT_JSON}")
            save_json_atomic(to_add, DAILY_OUTPUT_JSON)
        else:
            logging.info("Aucun nouvel IOC trouvé.")
            updated_data = existing_data
        print("="*50)

        # Calcul des dates min/max pour le tracking
        if updated_data:
            dates = [item.get("collected_at") for item in updated_data if item.get("collected_at")]
            if dates:
                tracking["earliest_modified"] = min(dates)
                tracking["latest_modified"] = max(dates)

        tracking["last_run"] = utc_now_iso()
        tracking["last_sync_success"] = tracking["last_run"]
        save_tracking_atomic(tracking)

        if os.path.exists(OLD_TRACKING_FILE):
            try:
                os.remove(OLD_TRACKING_FILE)
                logging.info(f"Ancien fichier de tracking supprimé : {OLD_TRACKING_FILE}")
            except:
                pass

    except Exception as e:
        logging.error(f"Erreur : {e}")

if __name__ == "__main__":
    main()
()