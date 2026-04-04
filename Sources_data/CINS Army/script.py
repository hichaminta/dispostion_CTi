import os
import json
import hashlib
import logging
from datetime import datetime, timezone

import requests

# Base directory setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CINS_URL = "https://cinsarmy.com/list/ci-badguys.txt"
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "cins_army_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
TIMEOUT = 30

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

def is_valid_ip(line: str) -> bool:
    parts = line.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True

def fetch_cins_list(url: str) -> list[str]:
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    ips = []
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if is_valid_ip(line):
            ips.append(line)
    return ips

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
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []

def save_json_atomic(data):
    tmp_file = OUTPUT_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, OUTPUT_FILE)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON : {e}")

def main():
    try:
        logging.info("Téléchargement de la liste CINS Army...")
        tracking = load_tracking()
        last_run = tracking.get("last_sync_success")
        if last_run:
            logging.info(f"Dernière exécution réussie : {last_run}")
        
        ips = fetch_cins_list(CINS_URL)
        logging.info(f"{len(ips)} IP récupérées")

        existing_data = load_existing_data()
        existing_indicators = {item["indicator"] for item in existing_data}
        
        collected_at = datetime.now(timezone.utc).isoformat()
        new_records = []
        
        for ip in ips:
            if ip not in existing_indicators:
                record = {
                    "indicator": ip,
                    "type": "ip",
                    "source": "cins_army",
                    "threat": "malicious_ip",
                    "collected_at": collected_at,
                    "hash": hashlib.sha256(f"cins_army:{ip}".encode("utf-8")).hexdigest()
                }
                new_records.append(record)
        
        if new_records:
            logging.info(f"{len(new_records)} nouveaux records trouvés.")
            updated_data = existing_data + new_records
            save_json_atomic(updated_data)
        else:
            logging.info("Aucun nouveau record trouvé.")

        tracking["last_sync_success"] = collected_at
        save_tracking_atomic(tracking)

        if os.path.exists(OLD_TRACKING_FILE):
            try:
                os.remove(OLD_TRACKING_FILE)
                logging.info(f"Ancien fichier de tracking supprimé : {OLD_TRACKING_FILE}")
            except:
                pass

    except Exception as e:
        logging.error(f"Erreur lors de l'exécution : {e}")

if __name__ == "__main__":
    main()