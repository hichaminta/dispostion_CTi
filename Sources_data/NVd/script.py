import requests
import json
import time
import os
import logging
import argparse
import threading
import sys
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
load_dotenv(find_dotenv())
API_KEY = os.getenv("NVD_API_KEY")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "nvd_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"nvd_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

write_lock = threading.Lock()
SAVE_EVERY = 500

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
    
    # Tentative migration si l'ancien fichier existe encore localement
    old_csv = os.path.join(SCRIPT_DIR, "last_run.csv")
    if os.path.exists(old_csv):
        try:
            import csv
            with open(old_csv, "r", encoding="utf-8") as f:
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
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

def fetch_nvd_page(params, retries=3):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for i in range(retries):
        try:
            r = requests.get(BASE_NVD_URL, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if i == retries - 1: raise e
            logging.warning(f"Tentative {i+1} échouée... ({e})")
            time.sleep(2)

def extract_cvss_list(vulnerability):
    metrics = vulnerability.get("cve", {}).get("metrics", {})
    cvss_list = []
    # Simplified extraction logic
    for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if v in metrics:
            for m in metrics[v]:
                cvss = m.get("cvssData", {})
                cvss_list.append({
                    "version": v[-2:].replace("V", ""),
                    "score": cvss.get("baseScore", "N/A"),
                    "vector": cvss.get("vectorString", "N/A")
                })
    return cvss_list

# =========================
# Logique de synchronisation
# =========================

def sync_nvd(start_date_str, end_date_str, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    start_index = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")

    logging.info(f"Démarrage synchronisation [{mode}] ({start_date_str} -> {end_date_str})...")

    while True:
        params = {
            "resultsPerPage": 500,
            "startIndex": start_index,
            "lastModStartDate": start_date_str,
            "lastModEndDate": end_date_str
        }
        
        try:
            data = fetch_nvd_page(params)
        except Exception as e:
            logging.error(f"Erreur page {start_index}: {e}")
            break
            
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities: break
            
        for vuln in vulnerabilities:
            scanned_count += 1
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            mod_date = cve.get("lastModified")

            if cve_id not in existing_ids:
                description = "N/A"
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "N/A")
                        break
                
                cve_item = {
                    "cve_id": cve_id,
                    "published": cve.get("published"),
                    "last_modified": mod_date,
                    "description": description,
                    "cvss": extract_cvss_list(vuln),
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }
                existing_data.append(cve_item)
                existing_ids.add(cve_id)
                new_records_total.append(cve_item)
                added_count += 1
                
                if mod_date:
                    if not earliest_seen or mod_date < earliest_seen:
                        earliest_seen = mod_date
                    if not latest_seen or mod_date > latest_seen:
                        latest_seen = mod_date

        total_results = data.get("totalResults", 0)
        logging.info(f"Progression : {start_index + len(vulnerabilities)} / {total_results}")
        
        if start_index + len(vulnerabilities) >= total_results: break
        start_index += 500
        time.sleep(0.6) # Rate limit

    return scanned_count, added_count, earliest_seen, latest_seen

def main():
    tracking = load_tracking()
    existing_data = load_existing_data()
    existing_ids = {item["cve_id"] for item in existing_data if "cve_id" in item}
    logging.info(f"Indexation : {len(existing_ids)} CVEs chargées.")

    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    # Par défaut on remonte 30 jours si pas de tracking
    latest_modified = tracking.get("latest_modified")
    if not latest_modified:
        latest_modified = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
    
    new_records_total = []

    try:
        # Phase 1 : Nouveautés
        sc1, ad1, e1, l1 = sync_nvd(latest_modified, now_str, existing_data, existing_ids, tracking, new_records_total, mode="AFTER")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        
        # Phase 2 : Historique (Backfill 120j si demandé --full)
        if "--full" in sys.argv:
            hist_start = (now - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
            sc2, ad2, e2, l2 = sync_nvd(hist_start, latest_modified, existing_data, existing_ids, tracking, new_records_total, mode="BEFORE")
            tracking["earliest_modified"] = e2
            tracking["latest_modified"] = l2

    except KeyboardInterrupt:
        logging.warning("Interruption.")

    # Finition
    now_iso = now.isoformat()
    tracking.update({
        "last_run": now_iso,
        "last_sync_success": now_iso
    })
    save_tracking_atomic(tracking)
    save_json_atomic(existing_data)
    
    if new_records_total:
        logging.info(f"Export journalier : {len(new_records_total)} items")
        save_json_atomic(new_records_total, DAILY_OUTPUT_JSON)

if __name__ == "__main__":
    main()