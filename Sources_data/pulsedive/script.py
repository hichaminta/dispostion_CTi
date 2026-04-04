import requests
import json
import os
import time
import csv
from dotenv import load_dotenv, find_dotenv
from datetime import datetime, timezone

# Charger .env depuis le dossier parent si nécessaire
load_dotenv(find_dotenv())

API_KEY = os.getenv("PULSEDIVE_API_KEY")

BASE_URL = "https://pulsedive.com/api/explore.php"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "pulsedive_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_CSV = os.path.join(SCRIPT_DIR, "last_run.csv")


def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    if os.path.exists(OLD_TRACKING_CSV):
        try:
            with open(OLD_TRACKING_CSV, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
                if len(rows) > 1 and rows[1]:
                    return {"last_sync_success": rows[1][0]}
        except:
            pass
    return {}

def save_tracking_atomic(tracking):
    tmp_file = TRACKING_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(tracking, f, indent=4, ensure_ascii=False)
    os.replace(tmp_file, TRACKING_FILE)

def load_existing_data():
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return data if isinstance(data, list) else []
            except:
                pass
    return []

def save_json_atomic(data):
    tmp_file = OUTPUT_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    os.replace(tmp_file, OUTPUT_FILE)


def fetch_iocs(limit=50):
    """
    Récupère des IOC depuis Pulsedive en maximisant les résultats
    """
    all_results = []
    
    # Itérer sur différents niveaux de risque pour maximiser l'extraction (limite API stricte = 50 par requête)
    risk_levels = ["critical", "high", "medium", "low", "none", "unknown"]

    for risk in risk_levels:
        print(f"Extraction des IOC avec risque: {risk}...")
        params = {
            "limit": limit,
            "pretty": 1,
            "key": API_KEY,
            "q": f"risk={risk}"
        }

        try:
            response = requests.get(BASE_URL, params=params)

            if response.status_code != 200:
                print(f"Erreur API pour risk={risk}:", response.status_code)
                continue

            data = response.json()

            results_list = data.get("results", [])
            print(f" - {len(results_list)} résultats trouvés pour {risk}")

            for item in results_list:
                record = {
                    "indicator": item.get("indicator"),
                    "type": item.get("type"),
                    "risk": item.get("risk"),
                    "threat": item.get("threat"),
                    "category": item.get("category"),
                    "first_seen": item.get("stamp_added"),
                    "last_seen": item.get("stamp_updated"),
                    "source": "pulsedive",
                    "collected_at": datetime.now(timezone.utc).isoformat()
                }

                all_results.append(record)
                
            time.sleep(1) # Pause pour éviter le rate limit
            
        except Exception as e:
            print(f"Erreur lors de la requête pour risk={risk}: {e}")

    # Déduplication basée sur l'indicateur
    unique_items = {}
    for item in all_results:
        unique_items[item["indicator"]] = item
        
    return list(unique_items.values())


def save_json(data):
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r") as f:
            existing = json.load(f)
    else:
        existing = []

    # Extraire les indicateurs existants pour éviter les doublons au niveau global
    existing_indicators = {item['indicator'] for item in existing}
    
    # Filtrer les nouvelles données
    new_data = [item for item in data if item['indicator'] not in existing_indicators]

    if not new_data:
        return 0

    combined = existing + new_data

    with open(OUTPUT_FILE, "w") as f:
        json.dump(combined, f, indent=4)
        
    return len(new_data)


def main():
    print("Extraction Pulsedive IOC (Maximisée)...")
    tracking = load_tracking()
    print(f"[i] Dernière exécution: {tracking.get('last_sync_success')}")

    iocs = fetch_iocs()

    if not iocs:
        print("Aucune donnée récupérée")
    else:
        existing = load_existing_data()
        existing_indicators = {item['indicator'] for item in existing}
        new_data = [item for item in iocs if item['indicator'] not in existing_indicators]
        
        if new_data:
            combined = existing + new_data
            save_json_atomic(combined)
            print(f"{len(new_data)} nouveaux IOC ajoutés (Total unique extrait : {len(iocs)})")
        else:
            print("Aucun nouveau record.")

    current_run = datetime.now(timezone.utc).isoformat()
    tracking["last_sync_success"] = current_run
    save_tracking_atomic(tracking)
    
    if os.path.exists(OLD_TRACKING_CSV):
        try: os.remove(OLD_TRACKING_CSV)
        except: pass
    print(f"[+] tracking.json mis à jour: {current_run}")


if __name__ == "__main__":
    main()