import os
import json
import hashlib
import logging
import sys
from datetime import datetime, timezone
import subprocess
import requests

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CINS_URL = "https://cinsarmy.com/list/ci-badguys.txt"
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "cins_army_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"cins_army_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
TIMEOUT = 30
SAVE_EVERY = 100

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# =========================
# Fonctions Utilitaires
# =========================

def is_valid_ip(line: str) -> bool:
    parts = line.split(".")
    if len(parts) != 4: return False
    for part in parts:
        if not part.isdigit(): return False
        value = int(part)
        if value < 0 or value > 255: return False
    return True

def fetch_cins_list(url: str) -> list[str]:
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    ips = []
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"): continue
        if is_valid_ip(line): ips.append(line)
    return ips

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

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

# =========================
# Logique de synchronisation
# =========================

def sync_cins(ips, existing_data, existing_indicators, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_ips = len(ips)

    logging.info(f"Démarrage synchronisation [{mode}] ({total_ips} IPs à traiter)...")

    for i, ip in enumerate(ips, 1):
        scanned_count += 1
        
        # Pour CINS, on n'a pas de date par IP dans le flux, 
        # donc on se base sur l'existence ou non.
        # Le mode "AFTER" vs "BEFORE" est ici plus structurel qu'incrémental par date API.
        
        if ip in existing_indicators:
            # Mise à jour du timestamp pour les données existantes
            record = existing_indicators[ip]
            record["collected_at"] = collected_at
            new_records_total.append(record)
            added_count += 1
            continue

        if ip not in existing_indicators:
            record = {
                "indicator": ip,
                "type": "ip",
                "source": "cins_army",
                "threat": "malicious_ip",
                "collected_at": collected_at,
                "hash": hashlib.sha256(f"cins_army:{ip}".encode("utf-8")).hexdigest()
            }
            existing_data.append(record)
            existing_indicators[ip] = record
            new_records_total.append(record)
            added_count += 1
            
            # Mise à jour des bornes
            if not earliest_seen or collected_at < earliest_seen:
                earliest_seen = collected_at
            if not latest_seen or collected_at > latest_seen:
                latest_seen = collected_at

        if added_count > 0 and added_count % SAVE_EVERY == 0:
            save_json_atomic(existing_data)
            tracking.update({
                "earliest_modified": earliest_seen,
                "latest_modified": latest_seen,
                "last_sync_attempt": datetime.now(timezone.utc).isoformat()
            })
            save_tracking_atomic(tracking)

    return scanned_count, added_count, earliest_seen, latest_seen

def main():
    if sys.platform == "win32":
        try: sys.stdout.reconfigure(encoding='utf-8')
        except: pass

    # 1. Charger données
    existing_data = load_existing_data()
    existing_indicators = {item["indicator"]: item for item in existing_data if "indicator" in item}
    logging.info(f"Indexation : {len(existing_indicators)} records chargés.")

    tracking = load_tracking()

    # 2. Récupérer liste
    try:
        ips = fetch_cins_list(CINS_URL)
        logging.info(f"{len(ips)} IPs récupérées de CINS Army.")
    except Exception as e:
        logging.error(f"Erreur téléchargement : {e}")
        return

    new_records_total = []

    try:
        # Phase unique pour CINS car pas de dates par item, mais on garde la structure
        sc_1, ad_1, e1, l1 = sync_cins(ips, existing_data, existing_indicators, tracking, new_records_total, mode="FULL_SYNC")
        tracking["earliest_modified"] = e1
        tracking["latest_modified"] = l1
        logging.info(f"Bilan : {ad_1} nouveaux records.")

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
    
    if new_records_total:
        logging.info(f"Export journalier : {len(new_records_total)} items")
        save_json_atomic(new_records_total, DAILY_OUTPUT_JSON)

    if os.path.exists(OLD_TRACK_FILE := os.path.join(SCRIPT_DIR, "last_run.csv")):
        os.remove(OLD_TRACK_FILE)

    # [AUTOMATION] Extraction directe des IOCs/CVEs après collecte
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "cins_army_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (cins_army_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    main()
