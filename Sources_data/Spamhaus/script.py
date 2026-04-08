import os
import json
import ipaddress
import logging
import sys
import subprocess
import threading
from datetime import datetime, timezone
import requests

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "spamhaus_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"spamhaus_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

SPAMHAUS_FEEDS = {
    "drop": "https://www.spamhaus.org/drop/drop.txt",
    "edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "dropv6": "https://www.spamhaus.org/drop/dropv6.txt",
}

SAVE_EVERY = 500

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
        except Exception: pass
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
        except Exception: pass
    return []

def save_json_atomic(data, filepath=None):
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur sauvegarde JSON ({target_file}) : {e}")

def download_feed(name: str, url: str) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CTI-Collector/1.0)"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.text

def detect_ioc_type(value: str) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
        return "ipv6" if net.version == 6 else "ipv4"
    except: return "unknown"

# =========================
# Logique de synchronisation
# =========================

def sync_spamhaus(feed_name, raw_text, url, existing_data, existing_keys, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    lines = raw_text.splitlines()
    total_lines = len(lines)

    logging.info(f"Démarrage synchronisation [{mode}] ({feed_name}: {total_lines} lignes)...")

    for idx, line in enumerate(lines, 1):
        scanned_count += 1
        line = line.strip()
        if not line or line.startswith(";"): continue

        parts = [p.strip() for p in line.split(";") if p.strip()]
        if not parts: continue

        network = parts[0]
        reference = parts[1] if len(parts) > 1 else None
        ioc_type = detect_ioc_type(network)
        if ioc_type == "unknown": continue

        key = (network, feed_name)
        if key in existing_keys:
            # Mise à jour du timestamp
            item = existing_keys[key]
            item["collected_at"] = collected_at
            new_records_total.append(item)
            added_count += 1
            continue

        if key not in existing_keys:
            print(f"[{idx}/{total_lines}] Nouveau range: {network}", end="\r")
            sys.stdout.flush()

            item = {
                "source": "spamhaus",
                "feed_name": feed_name,
                "ioc_value": network,
                "ioc_type": "ip_range",
                "ioc_subtype": ioc_type,
                "reference": reference,
                "collected_at": collected_at
            }
            existing_data.append(item)
            existing_keys[key] = item
            new_records_total.append(item)
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

    print("\n")
    return scanned_count, added_count, earliest_seen, latest_seen

def main():
    if sys.platform == "win32":
        try: sys.stdout.reconfigure(encoding='utf-8')
        except: pass

    # 1. Charger données et indexer
    existing_data = load_existing_data()
    existing_keys = {(item.get("ioc_value"), item.get("feed_name")): item for item in existing_data}
    logging.info(f"Indexation : {len(existing_keys)} ranges chargés.")

    tracking = load_tracking()
    new_records_total = []

    try:
        # Phase unique par feed
        for feed_name, url in SPAMHAUS_FEEDS.items():
            try:
                raw_text = download_feed(feed_name, url)
                sc1, ad1, e1, l1 = sync_spamhaus(feed_name, raw_text, url, existing_data, existing_keys, tracking, new_records_total, mode="FULL_SYNC")
                tracking["earliest_modified"] = e1
                tracking["latest_modified"] = l1
            except Exception as e:
                logging.error(f"Erreur {feed_name}: {e}")

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
    extractor_script = os.path.join(extraction_dir, "spamhaus_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (spamhaus_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    main()