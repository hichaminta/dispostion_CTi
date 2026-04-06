import requests
import json
import time
import os
import logging
import argparse
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# Base configuration
BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
load_dotenv(find_dotenv())
API_KEY = os.getenv("NVD_API_KEY")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "nvd_data.json")
# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"nvd_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
# OLD_TRACKING_FILE supprimé car passé au nouveau format

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
            if i == retries - 1:
                raise e
            logging.warning(f"Tentative {i+1} échouée, nouvel essai dans 2s... ({e})")
            time.sleep(2)

def extract_cvss_list(vulnerability):
    metrics = vulnerability.get("cve", {}).get("metrics", {})
    cvss_list = []
    # CVSS 3.1
    if "cvssMetricV31" in metrics:
        for m in metrics["cvssMetricV31"]:
            cvss = m.get("cvssData", {})
            cvss_list.append({"version": "3.1", "score": cvss.get("baseScore", "N/A"), "vector": cvss.get("vectorString", "N/A")})
    # CVSS 3.0
    elif "cvssMetricV30" in metrics:
        for m in metrics["cvssMetricV30"]:
            cvss = m.get("cvssData", {})
            cvss_list.append({"version": "3.0", "score": cvss.get("baseScore", "N/A"), "vector": cvss.get("vectorString", "N/A")})
    # CVSS 2.0
    if "cvssMetricV2" in metrics:
        for m in metrics["cvssMetricV2"]:
            cvss = m.get("cvssData", {})
            cvss_list.append({"version": "2.0", "score": cvss.get("baseScore", "N/A"), "vector": cvss.get("vectorString", "N/A")})
    return cvss_list

def main():
    parser = argparse.ArgumentParser(description="Extracteur NVD CVE")
    parser.add_argument("--days", type=int, default=30, help="Nombre de jours à remonter (par défaut 30)")
    parser.add_argument("--full", action="store_true", help="Extraction sur les 120 derniers jours (limite NVD)")
    args = parser.parse_args()

    tracking = load_tracking()
    last_run_str = tracking.get("latest_modified")
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    if last_run_str and not args.full:
        logging.info(f"Extraction incrémentale à partir de : {last_run_str}")
        start_date_str = last_run_str
    elif args.full:
        logging.info("Mode --full : extraction des 120 derniers jours (limite API).")
        start_date_str = (now - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000")
    else:
        logging.info(f"Extraction des {args.days} derniers jours par défaut.")
        start_date_str = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%S.000")

    existing_data = load_existing_data()
    existing_ids = {item["cve_id"] for item in existing_data if item.get("cve_id")}
    
    start_index = 0
    total_new = 0
    new_cves = [] # Collect new CVEs for daily export
    
    while True:
        params = {
            "resultsPerPage": 500,
            "startIndex": start_index,
            "lastModStartDate": start_date_str,
            "lastModEndDate": now_str
        }
        
        try:
            logging.info(f"Requête NVD Index {start_index}... (Période: {start_date_str} -> {now_str})")
            data = fetch_nvd_page(params)
        except Exception as e:
            logging.error(f"Échec critique sur la page {start_index} : {e}")
            break
            
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id: continue
            
            description = "N/A"
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "N/A")
                    break
            
            cvss_info = extract_cvss_list(vuln)
            
            if cve_id not in existing_ids:
                cve_item = {
                    "cve_id": cve_id,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "source": cve.get("sourceIdentifier", "N/A"),
                    "description": description,
                    "cvss": cvss_info,
                    "collected_at": now.isoformat()
                }
                existing_data.append(cve_item)
                new_cves.append(cve_item)
                existing_ids.add(cve_id)
                total_new += 1
        
        total_results = data.get("totalResults", 0)
        count_received = start_index + len(vulnerabilities)
        logging.info(f"Progression : {count_received} / {total_results}")
        
        if count_received >= total_results:
            break
        start_index += 500
        time.sleep(0.8) # Rate limit protection (NVD API est sensible)

    save_json_atomic(existing_data)
    
    # Save daily export if new CVEs were found
    if new_cves:
        logging.info(f"Sauvegarde des {len(new_cves)} nouvelles CVEs dans {DAILY_OUTPUT_JSON}")
        save_json_atomic(new_cves, DAILY_OUTPUT_JSON)
    
    tracking["latest_modified"] = now_str
    tracking["last_sync_success"] = now.isoformat()
    save_tracking_atomic(tracking)
    
    # Nettoyage de l'ancien CSV s'il existe encore
    old_csv = os.path.join(SCRIPT_DIR, "last_run.csv")
    if os.path.exists(old_csv):
        try:
            os.remove(old_csv)
            logging.info(f"Ancien fichier de tracking supprimé : {old_csv}")
        except:
            pass
    
    logging.info(f"Extraction terminée. {total_new} nouvelles CVEs extraites, {len(existing_data)} au total.")

if __name__ == "__main__":
    main()