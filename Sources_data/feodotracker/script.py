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

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "feodo_data.json")
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

def save_json_atomic(data):
    tmp_file = OUTPUT_JSON + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, OUTPUT_JSON)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON : {e}")

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
        last_run = tracking.get("last_sync_success")
        if last_run:
            logging.info(f"Dernière exécution : {last_run}")

        raw_text = download_feed()
        new_items = parse_feodo_json(raw_text)
        
        existing_data = load_existing_data()
        # Clé de déduplication : ioc_value + malware_family
        existing_keys = { (item["ioc_value"], item["malware_family"]) for item in existing_data }
        
        to_add = []
        for item in new_items:
            key = (item["ioc_value"], item["malware_family"])
            if key not in existing_keys:
                to_add.append(item)
        
        if to_add:
            logging.info(f"{len(to_add)} nouveaux IOCs ajoutés.")
            updated_data = existing_data + to_add
            save_json_atomic(updated_data)
        else:
            logging.info("Aucun nouvel IOC trouvé.")

        now_str = utc_now_iso()
        tracking["last_sync_success"] = now_str
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