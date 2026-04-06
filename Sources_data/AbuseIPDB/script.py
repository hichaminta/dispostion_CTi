import requests
import json
import os
import sys
import logging
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
load_dotenv(find_dotenv())
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "abuseipdb_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"abuseipdb_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

URL_BLACKLIST = "https://api.abuseipdb.com/api/v2/blacklist"
URL_CHECK = "https://api.abuseipdb.com/api/v2/check"

MAX_API_CALLS_CHECK = 100
SAVE_EVERY = 50

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
    
    # Migration
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

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

def get_ip_details(ip_addr, api_key):
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_addr, "maxAgeInDays": "90", "verbose": True}
    try:
        response = requests.get(URL_CHECK, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get("data", {})
    except Exception as e:
        logging.error(f"Erreur /check {ip_addr}: {e}")
    return None

# =========================
# Logique de synchronisation
# =========================

def sync_abuseipdb(ips_to_process, existing_data, existing_ips, tracking, new_entries_data, mode="AFTER"):
    added_count = 0
    updated_count = 0
    scanned_count = 0
    api_calls = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    last_run_dt = None
    if latest_seen:
        try:
            last_run_dt = datetime.fromisoformat(latest_seen.replace("Z", "+00:00"))
        except: pass

    now_str = datetime.now(timezone.utc).isoformat()
    total_ips = len(ips_to_process)

    logging.info(f"Démarrage synchronisation [{mode}] ({total_ips} IPs à scanner)...")

    for i, ip in enumerate(ips_to_process, 1):
        scanned_count += 1
        ip_addr = ip["ipAddress"]
        score = ip["abuseConfidenceScore"]
        last_reported_str = ip.get("lastReportedAt")
        
        last_reported_dt = None
        if last_reported_str:
            try:
                last_reported_dt = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
            except: pass

        # Logique de filtrage par phase
        if mode == "AFTER":
            # Nouveautés : seulement si après latest_seen
            if last_run_dt and last_reported_dt and last_reported_dt <= last_run_dt:
                continue
        elif mode == "BEFORE":
            # Historique : seulement si avant earliest_seen
            if earliest_seen and last_reported_str and last_reported_str >= earliest_seen:
                continue
        
        print(f"[{i}/{total_ips}] Vérification : {ip_addr}", end="\r")
        sys.stdout.flush()

        if ip_addr in existing_ips:
            existing_item = existing_ips[ip_addr]
            if last_reported_str and existing_item.get("lastReportedAt") != last_reported_str:
                existing_item["abuseConfidenceScore"] = score
                existing_item["lastReportedAt"] = last_reported_str
                existing_item["updated_at"] = now_str
                updated_count += 1
        else:
            details = None
            if api_calls < MAX_API_CALLS_CHECK:
                details = get_ip_details(ip_addr, API_KEY)
                api_calls += 1
            
            item_data = details if details else {
                "ipAddress": ip_addr,
                "abuseConfidenceScore": score,
                "lastReportedAt": last_reported_str,
                "extracted_at": now_str
            }
            existing_ips[ip_addr] = item_data
            existing_data.append(item_data)
            new_entries_data.append(item_data)
            added_count += 1
            
        # Mise à jour des bornes
        if last_reported_str:
            if not earliest_seen or last_reported_str < earliest_seen:
                earliest_seen = last_reported_str
            if not latest_seen or last_reported_str > latest_seen:
                latest_seen = last_reported_str

        if added_count > 0 and (added_count + updated_count) % SAVE_EVERY == 0:
            save_json_atomic(existing_data)
            tracking.update({
                "earliest_modified": earliest_seen,
                "latest_modified": latest_seen,
                "last_sync_attempt": datetime.now(timezone.utc).isoformat()
            })
            save_tracking_atomic(tracking)

    print("\n")
    return scanned_count, added_count, updated_count, earliest_seen, latest_seen

def main():
    if not API_KEY:
        logging.error("Clé API absente")
        return

    # 1. Charger données
    existing_data = load_existing_data()
    existing_ips = {item["ipAddress"]: item for item in existing_data if "ipAddress" in item}
    logging.info(f"Indexation : {len(existing_ips)} IPs chargées.")

    tracking = load_tracking()
    
    # 2. Récupérer Blacklist
    headers = {"Key": API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(URL_BLACKLIST, headers=headers)
        response.raise_for_status()
        blacklist_data = response.json().get("data", [])
    except Exception as e:
        logging.error(f"Erreur API : {e}")
        return

    new_entries_total = []

    try:
        # PHASE 1 : Nouveautés
        sc_1, ad_1, up_1, e1, l1 = sync_abuseipdb(blacklist_data, existing_data, existing_ips, tracking, new_entries_total, mode="AFTER")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        logging.info(f"Bilan Nouveautés : {ad_1} ajoutés, {up_1} mis à jour.")

        # PHASE 2 : Historique (On scanne tout ce qui n'est pas dans l'intervalle connu)
        sc_2, ad_2, up_2, e2, l2 = sync_abuseipdb(blacklist_data, existing_data, existing_ips, tracking, new_entries_total, mode="BEFORE")
        tracking["earliest_modified"] = e2
        tracking["latest_modified"] = l2
        logging.info(f"Bilan Historique : {ad_2} ajoutés, {up_2} mis à jour.")

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
    
    if new_entries_total:
        logging.info(f"Export journalier : {len(new_entries_total)} items")
        save_json_atomic(new_entries_total, DAILY_OUTPUT_JSON)

    if os.path.exists(OLD_TRACK_FILE := os.path.join(SCRIPT_DIR, "last_run.csv")):
        os.remove(OLD_TRACK_FILE)

if __name__ == "__main__":
    main()

