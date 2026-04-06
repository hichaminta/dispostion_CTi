import os
import json
import logging
import requests
import sys
import time
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(find_dotenv())
API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
API_URL = "https://www.virustotal.com/api/v3"

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "virustotal_data.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"virustotal_data_{today_str}.json")

TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# Throttling pour l'API publique (4 requêtes/minute = 15s d'attente)
IS_PUBLIC_KEY = True 
THROTTLE_DELAY = 15 
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
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur sauvegarde JSON ({target_file}) : {e}")

def vt_get(endpoint, params=None):
    headers = {"x-apikey": API_KEY}
    url = f"{API_URL}{endpoint}"
    response = requests.get(url, headers=headers, params=params, timeout=30)
    if response.status_code == 429:
        logging.warning("Quota atteint. Attente 60s...")
        time.sleep(60)
        return vt_get(endpoint, params)
    response.raise_for_status()
    return response.json()

# =========================
# Logique de synchronisation
# =========================

def sync_virustotal(targets, existing_data, existing_ids, tracking, new_records_total, mode="AFTER"):
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")
    
    collected_at = datetime.now(timezone.utc).isoformat()
    total_targets = len(targets)
    logging.info(f"Démarrage synchronisation [{mode}] ({total_targets} items à traiter)...")

    for i, tid in enumerate(targets, 1):
        scanned_count += 1
        target = targets[tid]
        ttype = target.get("type")

        if tid not in existing_ids:
            if IS_PUBLIC_KEY and i > 1:
                time.sleep(THROTTLE_DELAY)

            print(f"[{i}/{total_targets}] Extraction VT : {tid} ({ttype})", end="\r")
            sys.stdout.flush()

            try:
                report = vt_get(f"/{ttype}s/{tid}").get("data", {})
                if not report: continue
                
                attr = report.get("attributes", {})
                record = {
                    "source": "virustotal",
                    "id": tid,
                    "type": ttype,
                    "reputation": attr.get("reputation"),
                    "tags": attr.get("tags", []),
                    "malicious_votes": attr.get("last_analysis_stats", {}).get("malicious", 0),
                    "collected_at": collected_at
                }
                existing_data.append(record)
                existing_ids.add(tid)
                new_records_total.append(record)
                added_count += 1
                
                # Mise à jour des bornes
                if not earliest_seen or collected_at < earliest_seen:
                    earliest_seen = collected_at
                if not latest_seen or collected_at > latest_seen:
                    latest_seen = collected_at

            except Exception as e:
                logging.error(f"Erreur item {tid}: {e}")

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
    if not API_KEY:
        logging.error("VIRUSTOTAL_API_KEY manquante.")
        return

    # 1. Charger données
    existing_data = load_existing_data()
    existing_ids = {str(item.get("id")) for item in existing_data if item.get("id")}
    logging.info(f"Indexation : {len(existing_ids)} items chargés.")

    tracking = load_tracking()
    new_records_total = []

    # 2. Découverte (Comments & Notifications)
    targets = {}
    try:
        # Commentaires
        last_comment_id = tracking.get("last_comment_id")
        comments = vt_get("/comments", params={"limit": 25}).get("data", [])
        for c in comments:
            cid = c.get("id")
            if cid == last_comment_id: break
            parts = cid.split("-")
            if len(parts) >= 2:
                ctype_prefix = parts[0]
                target_id = parts[1]
                type_map = {"f": "file", "u": "url", "d": "domain", "i": "ip_address"}
                if ctype_prefix in type_map:
                    targets[target_id] = {"id": target_id, "type": type_map[ctype_prefix]}
        if comments: tracking["last_comment_id"] = comments[0].get("id")

        # Notifications (Hunting)
        last_notif_id = tracking.get("last_notification_id")
        try:
            notifs = vt_get("/intelligence/hunting_notifications", params={"limit": 10}).get("data", [])
            for n in notifs:
                nid = n.get("id")
                if nid == last_notif_id: break
                t = n.get("relationships", {}).get("item", {}).get("data", {})
                if t: targets[t["id"]] = t
            if notifs: tracking["last_notification_id"] = notifs[0].get("id")
        except: pass

    except Exception as e:
        logging.error(f"Erreur découverte : {e}")

    try:
        if targets:
            sc1, ad1, e1, l1 = sync_virustotal(targets, existing_data, existing_ids, tracking, new_records_total, mode="AFTER")
            tracking["earliest_modified"] = e1
            tracking["latest_modified"] = l1
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

if __name__ == "__main__":
    main()

