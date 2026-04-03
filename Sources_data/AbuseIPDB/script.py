import requests
import json
import os
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# Configuration
load_dotenv(find_dotenv())
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "abuseipdb_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
URL_BLACKLIST = "https://api.abuseipdb.com/api/v2/blacklist"
URL_CHECK = "https://api.abuseipdb.com/api/v2/check"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Impossible de lire le tracking JSON : {e}")
    
    # Tentative de migration depuis l'ancien CSV
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            import csv
            with open(OLD_TRACKING_FILE, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = [row for row in reader if row and len(row) > 0]
                if rows:
                    last_date = rows[-1][0]
                    if last_date != "date_extraction":
                        return {"latest_modified": last_date}
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

def get_ip_details(ip_addr, api_key):
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_addr,
        "maxAgeInDays": "90",
        "verbose": True
    }
    try:
        response = requests.get(URL_CHECK, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get("data", {})
    except Exception as e:
        logging.error(f"Erreur lors de la requête /check pour {ip_addr}: {e}")
    return None

def main():
    if not API_KEY:
        logging.error("Clé API ABUSEIPDB_API_KEY absente du fichier .env")
        return

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    
    logging.info("Récupération de la blacklist AbuseIPDB...")
    try:
        response = requests.get(URL_BLACKLIST, headers=headers)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logging.error(f"Erreur lors de la requête API : {e}")
        return

    tracking = load_tracking()
    last_run_str = tracking.get("latest_modified")
    last_run_dt = None
    
    if last_run_str:
        logging.info(f"Extraction incrémentale à partir de : {last_run_str}")
        try:
            last_run_dt = datetime.fromisoformat(last_run_str.replace("Z", "+00:00"))
        except ValueError:
            pass

    existing_data = load_existing_data()
    existing_ips = {item["ipAddress"]: item for item in existing_data}
    
    new_entries_count = 0
    updated_entries_count = 0
    api_calls = 0
    MAX_API_CALLS_CHECK = 100
    
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()
    
    latest_seen_dt = last_run_dt

    for ip in data.get("data", []):
        ip_addr = ip["ipAddress"]
        score = ip["abuseConfidenceScore"]
        last_reported_str = ip.get("lastReportedAt")
        
        last_reported_dt = None
        if last_reported_str:
            try:
                last_reported_dt = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
                if not latest_seen_dt or last_reported_dt > latest_seen_dt:
                    latest_seen_dt = last_reported_dt
            except ValueError:
                pass
        
        if last_run_dt and last_reported_dt and last_reported_dt <= last_run_dt:
            continue
        
        if ip_addr in existing_ips:
            existing_item = existing_ips[ip_addr]
            if last_reported_str and existing_item.get("lastReportedAt") != last_reported_str:
                existing_item["abuseConfidenceScore"] = score
                existing_item["lastReportedAt"] = last_reported_str
                existing_item["updated_at"] = now_str
                updated_entries_count += 1
        else:
            details = None
            if api_calls < MAX_API_CALLS_CHECK:
                logging.info(f"Obtention des détails pour {ip_addr}...")
                details = get_ip_details(ip_addr, API_KEY)
                api_calls += 1
            
            if details:
                details["extracted_at"] = now_str
                existing_ips[ip_addr] = details
            else:
                existing_ips[ip_addr] = {
                    "ipAddress": ip_addr,
                    "abuseConfidenceScore": score,
                    "lastReportedAt": last_reported_str,
                    "extracted_at": now_str
                }
            new_entries_count += 1
            if score >= 90:
                logging.warning(f"ALERTE : {ip_addr} (Confidence: {score})")

    if new_entries_count > 0 or updated_entries_count > 0:
        save_json_atomic(list(existing_ips.values()))
        logging.info(f"Extraction terminée. {new_entries_count} nouvelles IPs, {updated_entries_count} mises à jour.")
    else:
        logging.info("Aucune nouvelle IP ou mise à jour trouvée.")

    tracking["latest_modified"] = latest_seen_dt.isoformat() if latest_seen_dt else now_str
    tracking["last_sync_success"] = now_str
    save_tracking_atomic(tracking)
    
    # Nettoyage de l'ancien fichier s'il a été migré
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            os.remove(OLD_TRACKING_FILE)
            logging.info(f"Ancien fichier de tracking supprimé : {OLD_TRACKING_FILE}")
        except:
            pass

if __name__ == "__main__":
    main()
