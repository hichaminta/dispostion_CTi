import requests
import json
import time
import os
import logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# Base configuration
BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
load_dotenv(find_dotenv())
API_KEY = os.getenv("NVD_API_KEY")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "nvd_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
CISA_KEV_JSON = os.path.join(SCRIPT_DIR, "cisa.json")

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
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_file, OUTPUT_JSON)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON : {e}")

def load_cisa_kev():
    if not os.path.exists(CISA_KEV_JSON):
        logging.warning(f"Fichier CISA KEV absent : {CISA_KEV_JSON}")
        return set()
    try:
        with open(CISA_KEV_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        items = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    items = v
                    break
        
        kev = set()
        for obj in items:
            cve_id = obj.get("cveID") or obj.get("cve_id") or obj.get("id")
            if cve_id:
                kev.add(cve_id.strip().upper())
        return kev
    except Exception as e:
        logging.error(f"Erreur lors du chargement de CISA KEV : {e}")
        return set()

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
    tracking = load_tracking()
    last_run_str = tracking.get("latest_modified")
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    params = {"resultsPerPage": 500, "startIndex": 0}
    if last_run_str:
        logging.info(f"Extraction incrémentale à partir de : {last_run_str}")
        params["lastModStartDate"] = last_run_str
        params["lastModEndDate"] = now_str
    else:
        logging.info("Aucune date précédente trouvée, extraction des 7 derniers jours par défaut.")
        default_start = now - timedelta(days=7)
        params["lastModStartDate"] = default_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = now_str

    kev = load_cisa_kev()
    existing_data = load_existing_data()
    existing_ids = {item["cve_id"] for item in existing_data if item.get("cve_id")}
    
    start_index = 0
    total_new = 0
    
    while True:
        params["startIndex"] = start_index
        try:
            logging.info(f"Requête NVD Index {start_index}...")
            data = fetch_nvd_page(params)
        except Exception as e:
            logging.error(f"Échec critique : {e}")
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
                    "exploited": 1 if cve_id.upper() in kev else 0,
                    "collected_at": now.isoformat()
                }
                existing_data.append(cve_item)
                existing_ids.add(cve_id)
                total_new += 1
        
        total_results = data.get("totalResults", 0)
        logging.info(f"Progress : {start_index + len(vulnerabilities)} / {total_results}")
        
        if (start_index + len(vulnerabilities)) >= total_results:
            break
        start_index += 500
        time.sleep(0.6) # Rate limit protection

    save_json_atomic(existing_data)
    
    tracking["latest_modified"] = now_str
    tracking["last_sync_success"] = now.isoformat()
    save_tracking_atomic(tracking)
    
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            os.remove(OLD_TRACKING_FILE)
            logging.info(f"Ancien fichier de tracking supprimé : {OLD_TRACKING_FILE}")
        except:
            pass
    
    logging.info(f"Extraction terminée. {total_new} CVEs traitées, {len(existing_data)} au total.")

if __name__ == "__main__":
    main()
