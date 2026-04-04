import os
import json
import logging
import requests
import sys
import time
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# ── Configuration ──────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(find_dotenv())
API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
API_URL = "https://www.virustotal.com/api/v3"

# Les fichiers de sortie selon config.py
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "virustotal_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# Throttling pour l'API publique (4 requêtes/minute = 15s d'attente)
IS_PUBLIC_KEY = True # On assume public par défaut pour la sécurité des quotas
THROTTLE_DELAY = 15 

# ── Helpers ────────────────────────────────────────────────────────────────────
def now_utc_iso():
    return datetime.now(timezone.utc).isoformat()

def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Impossible de lire le tracking JSON : {e}")
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

# ── API Calls ──────────────────────────────────────────────────────────────────
def vt_get(endpoint, params=None):
    headers = {"x-apikey": API_KEY}
    url = f"{API_URL}{endpoint}"
    response = requests.get(url, headers=headers, params=params, timeout=30)
    
    if response.status_code == 429:
        logging.warning("Quota API VirusTotal atteint. Attente de 60s...")
        time.sleep(60)
        return vt_get(endpoint, params)
    
    response.raise_for_status()
    return response.json()

def fetch_notifications(limit=10):
    """Récupère les notifications Hunting (YARA)."""
    logging.info("Vérification des notifications Hunting...")
    try:
        data = vt_get("/intelligence/hunting_notifications", params={"filter": "tag:malicious", "limit": limit})
        return data.get("data", [])
    except Exception as e:
        logging.warning(f"Impossible de récupérer les notifications (Hunting peut être désactivé) : {e}")
        return []

def fetch_recent_comments(limit=10):
    """Récupère les derniers commentaires de la communauté."""
    logging.info("Vérification des derniers commentaires de la communauté...")
    try:
        data = vt_get("/comments", params={"limit": limit})
        return data.get("data", [])
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des commentaires : {e}")
        return []

def get_item_report(item_type, item_id):
    """Récupère le rapport complet pour un fichier, URL, domaine ou IP."""
    logging.info(f"Extraction des données détaillées pour {item_id}...")
    endpoint = f"/{item_type}s/{item_id}"
    try:
        report = vt_get(endpoint)
        return report.get("data", {})
    except Exception as e:
        logging.error(f"Erreur rapport {item_id} : {e}")
        return None

def get_item_relationships(item_type, item_id, relationship):
    """Récupère les relations (ex: contacted_ips)."""
    endpoint = f"/{item_type}s/{item_id}/{relationship}"
    try:
        data = vt_get(endpoint, params={"limit": 10})
        return data.get("data", [])
    except Exception:
        return []

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    if not API_KEY:
        logging.error("Clé API VIRUSTOTAL_API_KEY manquante dans .env")
        return

    existing_data = load_existing_data()
    existing_ids = { item.get("id") for item in existing_data if item.get("id") }
    
    tracking = load_tracking()
    last_comment_id = tracking.get("last_comment_id")
    last_notification_id = tracking.get("last_notification_id")

    # 1. Découverte de nouveaux items via commentaires
    new_items_to_fetch = []
    try:
        comments = fetch_recent_comments(limit=25)
        logging.info(f"{len(comments)} derniers commentaires récupérés.")
        for comment in comments:
            c_id = comment.get("id", "")
            if c_id == last_comment_id:
                break
            
            # L'ID d'un commentaire v3 est souvent au format : <type-prefix>-<target_id>-<random>
            # f = file (sha256), u = url (url_id), d = domain, i = ip
            parts = c_id.split("-")
            if len(parts) >= 2:
                ctype_prefix = parts[0]
                target_id = parts[1]
                
                type_map = {"f": "file", "u": "url", "d": "domain", "i": "ip_address"}
                if ctype_prefix in type_map:
                    new_items_to_fetch.append({"id": target_id, "type": type_map[ctype_prefix]})
        
        if comments:
            tracking["last_comment_id"] = comments[0].get("id")
    except Exception as e:
        logging.error(f"Erreur lors de la découverte via commentaires : {e}")

    # 2. Découverte via notifications
    notifications = fetch_notifications(limit=10)
    for notif in notifications:
        n_id = notif.get("id")
        if n_id == last_notification_id:
            break
        
        # Une notification est liée à un fichier
        target = notif.get("relationships", {}).get("item", {}).get("data", {})
        if target:
            new_items_to_fetch.append(target)
            
    if notifications:
        tracking["last_notification_id"] = notifications[0].get("id")

    # 3. Extraction des données pour les items uniques découverts
    unique_targets = {}
    for t in new_items_to_fetch:
        tid = t.get("id")
        if tid and tid not in existing_ids:
            unique_targets[tid] = t

    new_records = []
    collected_at = now_utc_iso()

    for tid, target in unique_targets.items():
        ttype = target.get("type")
        
        # Throttling
        if IS_PUBLIC_KEY and new_records:
            logging.info(f"Pause de {THROTTLE_DELAY}s pour respecter le quota API...")
            time.sleep(THROTTLE_DELAY)

        report = get_item_report(ttype, tid)
        if not report:
            continue
            
        attr = report.get("attributes", {})
        
        # Enrichissement avec des relations (seulement pour les fichiers pour cet exemple)
        relationships = {}
        if ttype == "file":
            relationships["contacted_ips"] = [r.get("id") for r in get_item_relationships("file", tid, "contacted_ips")]
            relationships["contacted_domains"] = [r.get("id") for r in get_item_relationships("file", tid, "contacted_domains")]

        record = {
            "source": "virustotal",
            "id": tid,
            "type": ttype,
            "attributes": {
                "names": attr.get("names", []),
                "reputation": attr.get("reputation"),
                "total_votes": attr.get("total_votes"),
                "last_analysis_stats": attr.get("last_analysis_stats"),
                "tags": attr.get("tags", []),
                "size": attr.get("size"),
                "type_description": attr.get("type_description"),
                "first_submission_date": attr.get("first_submission_date"),
                "last_analysis_results": { k: v.get("result") for k, v in attr.get("last_analysis_results", {}).items() if v.get("result") }
            },
            "relationships": relationships,
            "collected_at": collected_at
        }
        new_records.append(record)

    if new_records:
        logging.info(f"{len(new_records)} nouveaux items importés de VirusTotal.")
        updated_data = existing_data + new_records
        save_json_atomic(updated_data)
    else:
        logging.info("Aucun nouvel item découvert sur VirusTotal.")

    tracking["last_sync_success"] = collected_at
    save_tracking_atomic(tracking)

if __name__ == "__main__":
    main()
