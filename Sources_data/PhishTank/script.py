import requests
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv, find_dotenv

# ── Configuration ──────────────────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=False)

API_KEY = os.getenv("PHISHTANK_API_KEY", "")
# PhishTank requires a custom User-Agent for programmatic access
USER_AGENT = f"phishtank/{API_KEY}" if API_KEY else "phishtank/python-extraction-script"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "phishtank_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_DATA_FILE = os.path.join(SCRIPT_DIR, "verified_online.json")

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json"

def load_tracking():
    """Charge le tracking JSON."""
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_tracking_atomic(tracking: dict):
    """Sauvegarde le tracking JSON de manière atomique."""
    tmp_file = TRACKING_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(tracking, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, TRACKING_FILE)
    except Exception as e:
        print(f"Erreur tracking : {e}")

def save_json_atomic(data: dict):
    """Sauvegarde la base de données JSON de manière atomique."""
    tmp_file = DB_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, DB_FILE)
    except Exception as e:
        print(f"Erreur sauvegarde JSON : {e}")

def load_data():
    """Charge la base de données existante (ou migre l'ancien fichier)."""
    # 1. Si la nouvelle base existe, on l'utilise
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                print(f"Warning: {DB_FILE} is invalid. Starting empty.")
                return []
                
    # 2. Sinon, on regarde si on peut migrer l'ancien verified_online.json
    if os.path.exists(OLD_DATA_FILE):
        print(f"Migration de l'ancien fichier {OLD_DATA_FILE}...")
        try:
            with open(OLD_DATA_FILE, "r", encoding="utf-8") as f:
                raw_list = json.load(f)
                if isinstance(raw_list, list):
                    print(f"  ✓ {len(raw_list)} entrées migrées.")
                    return raw_list
        except Exception as e:
            print(f"Erreur migration : {e}")
            
    return []

def fetch_phishtank_data():
    """Récupère le flux JSON de PhishTank."""
    # HTTPS est souvent plus stable pour les redirections CDN
    url = PHISHTANK_URL.replace("http://", "https://")
    print(f"Fetching PhishTank data from {url}...")
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }
    
    try:
        # allow_redirects=True est par défaut, mais on s'assure d'un timeout généreux
        response = requests.get(url, headers=headers, timeout=120, allow_redirects=True)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print("  ✗ Erreur 404 : Le dump PhishTank n'est pas encore prêt ou l'URL CDN a expiré. Réessayez dans quelques minutes.")
        else:
            print(f"  ✗ Erreur HTTP lors du téléchargement PhishTank : {e}")
        return []
    except Exception as e:
        print(f"  ✗ Erreur lors du téléchargement PhishTank : {e}")
        return []

def update_database():
    # Fix Windows encoding issues for logs
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    print("=" * 60)
    print("Mise à jour de la base PhishTank")
    print("=" * 60)

    tracking = load_tracking()
    tracking["last_sync_attempt"] = datetime.now().isoformat()
    
    data = load_data()
    # On s'assure que data est bien une liste
    if not isinstance(data, list):
        data = []
        
    existing_ids = {str(item.get("phish_id")) for item in data if item.get("phish_id")}
    
    raw_list = fetch_phishtank_data()
    if not raw_list:
        print("  ! Aucune donnée récupérée ce tour-ci (PhishTank est peut-être en cours de mise à jour).")
        # On sauvegarde quand même l'attempt
        save_tracking_atomic(tracking)
        return

    new_entries = 0
    updated_entries = 0
    new_phish_items = []
    total_raw = len(raw_list)
    print(f"  → Traitement de {total_raw} entrées reçues...")
    
    for i, item in enumerate(raw_list, 1):
        phish_id = str(item.get("phish_id"))
        if not phish_id or phish_id == "None":
            continue
            
        print(f"[{i}/{total_raw}] Vérification : {phish_id}", end="\r")
        sys.stdout.flush()

        if phish_id not in existing_ids:
            data.append(item)
            existing_ids.add(phish_id)
            new_phish_items.append(item)
            new_entries += 1
        else:
            updated_entries += 1
            
    print("\n" + "="*50)
    if new_entries > 0 or updated_entries > 0:
        save_json_atomic(data)
        print(f"[OK] Ajout de {new_entries} nouveaux phishings.")
        if new_phish_items:
            print("\nDétail des nouveaux phishings :")
            # On affiche les 20 premiers s'il y en a trop
            display_limit = 20
            for item in new_phish_items[:display_limit]:
                print(f" [+] {item['phish_id']} - {item['url'][:70]}...")
            if len(new_phish_items) > display_limit:
                print(f" ... et {len(new_phish_items) - display_limit} autres.")

        print(f"\n[OK] Total en base : {len(data)} phishings.")
    else:
        print(f"\nMise à jour terminée. Aucun changement. Total : {len(data)}")
    print("="*50)

    # Calcul des dates min/max pour le tracking
    if data:
        # submission_time est dans le format "2026-04-04T..."
        dates = [item.get("submission_time") for item in data if item.get("submission_time")]
        if dates:
            tracking["earliest_modified"] = min(dates)
            tracking["latest_modified"] = max(dates)

    # Mise à jour du tracking
    now_str = datetime.now().isoformat()
    tracking["last_run"] = now_str
    tracking["last_sync_success"] = now_str
    save_tracking_atomic(tracking)
    print(f"[+] tracking.json mis à jour: {now_str}")
    print("=" * 60)

if __name__ == "__main__":
    update_database()
