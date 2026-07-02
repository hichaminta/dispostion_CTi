import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import requests
import time
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CVEEnrichment")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources")

DOTENV_PATH = os.path.join(BASE_DIR, ".env")

def get_nvd_api_key():
    if os.path.exists(DOTENV_PATH):
        try:
            with open(DOTENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("NVD_API_KEY="):
                        return line.split("=")[1].strip()
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du .env : {e}")
    return None

NVD_API_KEY = get_nvd_api_key()
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TRACKING_DIR = os.path.join(BASE_DIR, "tracking", "tracking_enrichment")

def get_tracking_file(source):
    return os.path.join(TRACKING_DIR, f"{source}_tracking.json")

def load_source_tracking(source):
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)
    path = get_tracking_file(source)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_source_tracking(source, data):
    path = get_tracking_file(source)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def fetch_cve_details(cve_id):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    
    params = {"cveId": cve_id}
    try:
        logger.info(f"Appel API NVD pour {cve_id}...")
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                
                # Extraction de la description (anglais)
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        description = d.get("value")
                        break
                
                # Extraction du score CVSS
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                cvss_version = None
                
                # PrioritÃ© : v3.1 > v3.0 > v2.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    v_metrics = metrics.get(version, [])
                    if v_metrics:
                        # PrÃ©fÃ©rer le type 'Primary' si disponible
                        primary = [m for m in v_metrics if m.get("type") == "Primary"]
                        metric = primary[0] if primary else v_metrics[0]
                        cvss_data = metric.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        cvss_version = cvss_data.get("version")
                        break
                
                return {
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_version": cvss_version
                }
            else:
                logger.warning(f"Aucune donnÃ©e trouvÃ©e pour {cve_id}")
        elif response.status_code == 403:
            logger.error(f"ClÃ© API invalide ou limite de dÃ©bit atteinte (403) pour {cve_id}")
        elif response.status_code == 429:
            logger.error(f"Rate limited (429). Pause nÃ©cessaire.")
            time.sleep(10)
        else:
            logger.error(f"Erreur API {response.status_code} pour {cve_id}")
    except Exception as e:
        logger.error(f"Exception lors de l'appel API pour {cve_id} : {e}")
    
    return None

def enrich_cves():
    cve_cache = {}
    
    # On parcourt tous les fichiers JSON du dossier d'enrichissement
    import glob
    json_files = glob.glob(os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources", "*", "enrichment", "*.json"))
    for filepath in json_files:
        filename = os.path.basename(filepath)
        if not os.path.exists(filepath):
            logger.warning(f"Fichier {filename} introuvable dans extraction/enrichment")
            continue
            
        logger.info(f"Enrichissement CVE du fichier : {filename}")
        source = os.path.basename(os.path.dirname(os.path.dirname(filepath)))
        
        # Tracking logic
        source_data = load_source_tracking(source)
        if "cve_enrichment" not in source_data:
            source_data["cve_enrichment"] = {
                "first_cve_date": None,
                "last_cve_date": None,
                "total_cves": 0,
                "last_run": None,
                "files_processed": []
            }
        
        # Skip if already processed and not forced (optional)
        # if filename in source_data["cve"]["files_processed"]:
        #     logger.info(f"Skipping {filename} (already processed for CVE)")
        #     continue

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception as e:
            logger.error(f"Impossible de lire {filename} : {e}")
            continue

        if not isinstance(records, list):
            logger.error(f"Le format de {filename} n'est pas une liste.")
            continue

        modified_count = 0
        for record in records:
            cves = record.get("cves", [])
            if not cves:
                continue
            
            for cve_obj in cves:
                cve_id = cve_obj.get("id")
                if not cve_id:
                    continue
                
                # On vÃ©rifie si l'enrichissement est nÃ©cessaire
                # (si score manque dans attributes ou dans ioc_enrichment)
                attrs = record.get("attributes", {})
                ioc_enrich = cve_obj.get("ioc_enrichment", {})
                
                # Si on a dÃ©jÃ  un score dans l'un des deux, on considÃ¨re que c'est bon
                if attrs.get("cvss_score") or ioc_enrich.get("cvss_score"):
                    # Mais on s'assure quand mÃªme que ioc_enrichment est rempli s'il Ã©tait vide
                    if not ioc_enrich.get("cvss_score") and attrs.get("cvss_score"):
                        ioc_enrich["cvss_score"] = attrs.get("cvss_score")
                        ioc_enrich["cvss_vector"] = attrs.get("cvss_vector")
                        ioc_enrich["cvss_version"] = attrs.get("cvss_version")
                        ioc_enrich["description"] = record.get("description")
                        modified_count += 1
                    continue
                
                if cve_id in cve_cache:
                    details = cve_cache[cve_id]
                else:
                    details = fetch_cve_details(cve_id)
                    cve_cache[cve_id] = details
                    # Respecter la limite de dÃ©bit de la NVD (0.6s avec clÃ©)
                    time.sleep(0.8)
                
                if details:
                    now_iso = datetime.now().isoformat()
                    if details.get("cvss_score"):
                        # Mise Ã  jour des attributs globaux
                        attrs["cvss_score"] = details["cvss_score"]
                        attrs["cvss_vector"] = details["cvss_vector"]
                        attrs["cvss_version"] = details["cvss_version"]
                        attrs["tlp"] = "TLP:CLEAR"
                        attrs["enriched_at"] = now_iso
                        
                        # Mise Ã  jour de l'enrichissement spÃ©cifique Ã  l'indicateur
                        ioc_enrich["cvss_score"] = details["cvss_score"]
                        ioc_enrich["cvss_vector"] = details["cvss_vector"]
                        ioc_enrich["cvss_version"] = details["cvss_version"]
                        ioc_enrich["description"] = details["description"]
                        ioc_enrich["tlp"] = "TLP:CLEAR"
                        ioc_enrich["enriched_at"] = now_iso
                        
                        # Mise Ã  jour du rÃ©sumÃ©
                        record["summary"] = f"CVE Enrichment: {cve_id} | CVSS: {details['cvss_score']}"
                    
                    if details.get("description"):
                        record["description"] = details["description"]
                    
                    record["attributes"] = attrs
                    cve_obj["ioc_enrichment"] = ioc_enrich
                    modified_count += 1

        # Update tracking always
        source_data["cve_enrichment"]["last_run"] = datetime.now().isoformat()
        if filename not in source_data["cve_enrichment"]["files_processed"]:
            source_data["cve_enrichment"]["files_processed"].append(filename)
        source_data["cve_enrichment"]["total_cves"] = sum(len(r.get("cves", [])) for r in records)
        save_source_tracking(source, source_data)

        if modified_count > 0:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(records, f, ensure_ascii=False, indent=4)
                logger.info(f"[OK] {filename} mis Ã  jour avec {modified_count} enrichissements CVE.")
            except Exception as e:
                logger.error(f"Erreur lors de l'Ã©criture de {filename} : {e}")
        else:
            logger.info(f"Aucune modification nÃ©cessaire pour {filename}.")

if __name__ == "__main__":
    enrich_cves()
