import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import requests
import json
import time
import os
import sys
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv
import subprocess

# ── Configuration du logging ──────────────────────────────────────────────────
import logging
logging.basicConfig(encoding="utf-8", 
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ── Configuration et Chargement ──────────────────────────────────────────────
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
load_dotenv(find_dotenv())
API_KEY = os.getenv("NVD_API_KEY")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "nvd_data.json")

# Daily export configuration (optional, like AbuseIPDB)
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"nvd_data_{today_str}.json")

def _get_mongo_tracker():
    import sys
    import os
    # Ensure utils is in path dynamically
    project_root = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    try:
        from utils.mongo_tracking import SourceTracker
        source_name = os.path.basename(SCRIPT_DIR)
        return SourceTracker(source_name)
    except Exception as e:
        logging.error(f"Failed to load MongoTracker: {e}")
        return None

def load_tracking():
    tracker = _get_mongo_tracker()
    if tracker:
        return tracker.get_tracking()
    return {}

def save_tracking_atomic(tracking):
    tracker = _get_mongo_tracker()
    if tracker:
        tracker.save_tracking(tracking)


def fetch_cves(params, retries=5):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for i in range(retries):
        try:
            r = requests.get(BASE_URL, params=params, headers=headers, timeout=60)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if i == retries - 1:
                raise e
            
            # Temps d'attente progressif (backoff exponentiel) : 5s, 10s, 15s...
            sleep_time = 5 * (i + 1)
            logging.warning(f"Erreur API (tentative {i+1}/{retries}): {e}")
            logging.info(f"NVD est peut-être surchargé. Attente de {sleep_time} secondes avant la prochaine tentative...")
            time.sleep(sleep_time)

def extract_cvss_list(vulnerability):
    """Extrait toutes les métriques CVSS de la vulnérabilité."""
    metrics = vulnerability.get("cve", {}).get("metrics", {})
    cvss_list = []
    
    # Récupérer CVSS 4.0
    if "cvssMetricV40" in metrics:
        cvss = metrics["cvssMetricV40"][0].get("cvssData", {})
        cvss_list.append({
            "version": "4.0",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
    
    # Récupérer CVSS 3.1 ou 3.0
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_list.append({
            "version": "3.1",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_list.append({
            "version": "3.0",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
    
    # Récupérer CVSS 2.0
    if "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_list.append({
            "version": "2.0",
            "score": cvss.get("baseScore", "N/A"),
            "vector": cvss.get("vectorString", "N/A")
        })
        
    return cvss_list

def load_existing_json():
    """Charge les résultats existants si le fichier JSON existe, sinon retourne la liste."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logging.error(f"Erreur lors du chargement de {OUTPUT_JSON} : {e}")
    return []

def save_json_atomic(data, filepath=None):
    """Sauvegarde les données JSON de manière atomique."""
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

def extract_all(limit=None):
    tracking = load_tracking()
    last_date = tracking.get("last_run")
    
    new_extracted_data = []
    start_index = 0
    results_per_page = 500
    
    # Utilisation du paramètre UTC recommandé par l'API NVD
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    
    force_full = "--full" in sys.argv

    if force_full:
        logging.info("Mode --full activé : Téléchargement de TOUTE la base NVD depuis le début.")
        # Aucun paramètre temporel n'est ajouté
    elif last_date:
        logging.info(f"Extraction incrémentale à partir de : {last_date}")
        params["lastModStartDate"] = last_date
        params["lastModEndDate"] = now_str
    else:
        logging.info("Aucune date précédente trouvée dans tracking.json et pas de flag --full.")
        logging.info("Utilisation d'une date par défaut (les 7 derniers jours).")
        default_start = now - timedelta(days=7)
        params["lastModStartDate"] = default_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = now_str

    logging.info("Début de l'extraction...")
    
    total_processed = 0
    while True:
        params["startIndex"] = start_index
        try:
            data = fetch_cves(params)
        except Exception as e:
            logging.error(f"Échec critique : {e}")
            break
            
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            published = cve.get("published")
            source = cve.get("sourceIdentifier", "N/A")
            last_modified = cve.get("lastModified")
            
            # Extraction de la description en anglais
            description = "N/A"
            descriptions = cve.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "N/A")
                    break
            
            cvss_info = extract_cvss_list(vuln)
            
            # Enregistrer même si y'a pas de CVSS (les CVE très récentes peuvent ne pas en avoir tout de suite)
            new_extracted_data.append({
                "cve_id": cve_id,
                "published": published,
                "lastModified": last_modified,
                "source": source,
                "description": description,
                "cvss": cvss_info,
                "collected_at": now.isoformat()
            })
            
            total_processed += 1
            if limit and total_processed >= limit:
                break
        
        total_results = data.get("totalResults", 0)
        logging.info(f"Processed: {total_processed} / {total_results} | New CVSS Extracted: {len(new_extracted_data)}")
        
        if total_processed >= total_results or (limit and total_processed >= limit):
            break
            
        start_index += results_per_page
        
        # Le NVD est très instable. Même avec une clé API, il est conseillé de ne pas saturer.
        # 1.5 seconde d'attente pour être beaucoup plus doux avec leurs serveurs.
        time.sleep(1.5) 
        
    if not new_extracted_data:
        logging.info("Aucune nouvelle vulnérabilité CVE trouvée depuis la dernière exécution.")
    else:
        # Fusion avec les données existantes pour maintenir la liste complète si on veut
        # Ou alors on écrase ? Les extractors de l'auteur ont l'habitude d'append à un array
        existing_data = load_existing_json()
        
        # Mettre à jour les CVE existants ou ajouter les nouveaux
        existing_cves = {item["cve_id"]: item for item in existing_data if "cve_id" in item}
        for item in new_extracted_data:
            existing_cves[item["cve_id"]] = item
            
        final_data = list(existing_cves.values())
        save_json_atomic(final_data)
        
        # Save daily output
        save_json_atomic(new_extracted_data, DAILY_OUTPUT_JSON)
        
        logging.info(f"\nExtraction terminée ! Total {len(final_data)} entrées CVSS sauvegardées.")

    # Sauvegarde de la date pour la prochaine fois
    tracking["last_run"] = now_str
    save_tracking_atomic(tracking)
    
    # [AUTOMATION] Lancement de l'extracteur
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "nvd_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (nvd_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    try:
        extract_all() 
    except Exception as e:
        logging.error(f"Erreur globale : {e}")
