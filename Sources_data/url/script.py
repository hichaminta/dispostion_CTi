import requests
import json
import csv
import os
import io
import sys
import zipfile
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv, find_dotenv

# ── Configuration ──────────────────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=False)

# On tente d'utiliser la clé URLhaus ou la clé ThreatFox (souvent la même Auth-Key abuse.ch)
API_KEY = os.getenv("URLHAUS_API_KEY") or os.getenv("THREATFOX_API_KEY", "")

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, "urlhaus_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# URLhaus JSON exports
URLHAUS_JSON_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
URLHAUS_ONLINE_JSON_URL = "https://urlhaus.abuse.ch/downloads/json/"
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"
# Bulk export API (v2) - nécessite l'Auth-Key dans l'URL
BULK_EXPORT_URL_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{api_key}/full.json.zip"

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
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                print(f"Warning: {DB_FILE} is not a valid JSON. Starting with empty database.")
                return []
    return []

def fetch_json_data(url: str):
    """Télécharge et parse le flux JSON (éventuellement zippé) d'URLhaus."""
    print(f"Fetching data from {url}...")
    response = requests.get(url, timeout=600)  # On augmente le timeout pour le full dump
    response.raise_for_status()
    
    content = response.content
    
    # Si c'est un ZIP (ou si l'URL se finit par / ce qui arrive sur URLhaus), on tente de décompresser
    if url.endswith('.zip') or response.headers.get('Content-Type') == 'application/zip' or content.startswith(b'PK\x03\x04'):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                # On cherche le fichier JSON
                files = [f for f in z.namelist() if f.endswith('.json')]
                if not files:
                    files = [z.namelist()[0]]
                
                with z.open(files[0]) as f:
                    content = f.read()
        except zipfile.BadZipFile:
            pass

    # Décodage JSON
    try:
        data = json.loads(content)
        # URLhaus JSON dump est soit une liste directe, soit un objet avec une clé "urls"
        # soit une map massive {"ID": {...}}
        if isinstance(data, dict):
            if "urls" in data:
                return data["urls"]
            else:
                # Si c'est un dict sans "urls", on prend les clés comme IDs
                results = []
                for key, val in data.items():
                    # Si val est une liste [ {...} ], on prend le premier élément
                    if isinstance(val, list) and len(val) > 0:
                        val = val[0]
                    if isinstance(val, dict):
                        if "id" not in val:
                            val["id"] = key
                        results.append(val)
                return results
        elif isinstance(data, list):
            return data
        else:
            print("Format JSON inconnu (ni liste ni objet).")
            return []
    except Exception as e:
        print(f"Erreur lors du parsing JSON : {e}")
        return []

def fetch_recent_urls():
    """Récupère les URLs des 30 derniers jours (JSON)."""
    return fetch_json_data(URLHAUS_JSON_URL)

def fetch_active_urls():
    """Récupère les URLs actuellement en ligne (JSON)."""
    return fetch_json_data(URLHAUS_ONLINE_JSON_URL)

def fetch_bulk_export():
    """Télécharge l'export complet via l'API v2 (nécessite une clé)."""
    if not API_KEY or API_KEY == "your_auth_key_here":
        print("  ✗ Aucune clé API valide pour l'export Bulk.")
        return []
        
    url = BULK_EXPORT_URL_TEMPLATE.format(api_key=API_KEY)
    return fetch_json_data(url)

def fetch_csv_urls():
    """
    Récupère le dump complet (CSV public) comme solution de secours pour l'historique.
    Note: Contient moins de métadonnées que le JSON (pas de payloads).
    """
    print(f"Fetching historical data from {URLHAUS_CSV_URL}...")
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=600)
        response.raise_for_status()
        
        # Le CSV public commence par des commentaires (#)
        lines = response.text.splitlines()
        data_lines = [line for line in lines if line and not line.startswith("#")]
        
        reader = csv.DictReader(data_lines, fieldnames=["id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link", "reporter"])
        results = []
        for row in reader:
            results.append(row)
        return results
    except Exception as e:
        print(f"  ✗ Erreur lors du fetch CSV : {e}")
        return []

def update_database():
    # Fix Windows encoding issues for logs
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    print("=" * 60)
    print("Mise à jour de la base URLHaus (JSON)")
    print("=" * 60)

    is_full_sync = "--full" in sys.argv
    data = load_data()
    tracking = load_tracking()
    existing_ids = {str(item.get("id")) for item in data if item.get("id")}
    initial_count = len(data)
    
    # Si la base est vide ou mode --full, on cherche le plus gros export disponible
    if is_full_sync or initial_count == 0:
        is_full_sync = True
        urls = []
        
        # 1. Tentative Bulk Export (le graal: full history + enriched)
        if API_KEY:
            print("  → Tentative de récupération de l'export BULK (v2 API)...")
            urls = fetch_bulk_export()
            
        # 2. Si échec ou pas de clé, tentative CSV public (full history moderate enrichment)
        if not urls:
            print("  → Récupération du dump CSV public (Historique Complet)...")
            urls = fetch_csv_urls()
            
        # 3. Si toujours rien, fallback sur le JSON "Online" (active only)
        if not urls:
            print("  → Fallback : Récupération des URLs actives (Online JSON)...")
            urls = fetch_active_urls()
            
        if not urls:
            print("  ✗ Impossible de récupérer des données pour la synchronisation complète.")
            return
    else:
        print("  → Récupération des URLs récentes (JSON 30 jours)...")
        try:
            urls = fetch_recent_urls()
        except Exception as e:
            print(f"  ✗ Erreur lors du téléchargement récent : {e}")
            return

    new_entries = 0
    updated_entries = 0
    new_urls_list = []
    total_raw = len(urls)
    print(f"  → Traitement de {total_raw} URLs reçues...")
    
    for i, item in enumerate(urls, 1):
        url_id = str(item.get("id"))
        
        if not url_id or url_id == "None":
            continue

        print(f"[{i}/{total_raw}] Vérification : {url_id}", end="\r")
        sys.stdout.flush()

        # Extraction de toutes les données possibles
        url_val = item.get("url")
        extracted_host = urlparse(url_val).netloc if url_val else None

        entry_data = {
            "dateadded": item.get("date_added", item.get("dateadded")), # Fallback si deja présent
            "url": url_val,
            "urlhaus_link": item.get("urlhaus_reference"),
            "url_status": item.get("url_status"),
            "last_online": item.get("last_online"),
            "threat": item.get("threat"),
            "tags": item.get("tags", []),
            "reporter": item.get("reporter"),
            # Nouvelles données riches
            "host": item.get("host") or extracted_host,
            "ip_address": item.get("ip_address"),
            "as_number": item.get("as_number"),
            "country": item.get("country"),
            "blacklists": item.get("blacklists", {}),
            "payloads": item.get("payloads", [])
        }

        if url_id not in existing_ids:
            data.append(entry_data)
            existing_ids.add(url_id)
            new_urls_list.append(entry_data)
            new_entries += 1
        else:
            updated_entries += 1
            
    print("\n" + "="*50)
    if new_entries > 0 or updated_entries > 0:
        save_json_atomic(data)
        print(f"[OK] Ajout de {new_entries} nouvelles URLs.")
        if new_urls_list:
            print("\nDétail des nouvelles URLs :")
            display_limit = 20
            for item in new_urls_list[:display_limit]:
                print(f" [+] {item['url'][:70]}... ({item['threat']})")
            if len(new_urls_list) > display_limit:
                print(f" ... et {len(new_urls_list) - display_limit} autres.")

        print(f"  ✓ Total en base : {len(data)} URLs")
    else:
        print(f"\nMise à jour terminée. Aucun changement. Total : {len(data)}")
    print("="*50)

    # Mise à jour du tracking
    tracking = load_tracking()
    tracking["last_sync_attempt"] = datetime.now().isoformat()
    
    # Calcul des dates min/max pour le tracking
    if data:
        # dateadded est au format "YYYY-MM-DD HH:MM:SS"
        dates = [item.get("dateadded") for item in data if item.get("dateadded")]
        if dates:
            tracking["earliest_modified"] = min(dates)
            tracking["latest_modified"] = max(dates)

    now_str = datetime.now().isoformat()
    tracking["last_run"] = now_str
    tracking["last_sync_success"] = now_str
    save_tracking_atomic(tracking)
    print(f"[+] tracking.json mis à jour: {now_str}")
    print("=" * 60)

if __name__ == "__main__":
    update_database()