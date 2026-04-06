import requests
import json
import os
import csv
import sys
import io
import zipfile
from datetime import datetime, timedelta
from dotenv import load_dotenv, find_dotenv

# ── Configuration ──────────────────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=False)

API_KEY      = os.getenv("THREATFOX_API_KEY", "")
API_URL      = "https://threatfox-api.abuse.ch/api/v1/"
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON  = os.path.join(SCRIPT_DIR, "threatfox_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

# Nombre de jours d'IOCs à récupérer lors de la première exécution (Limite API = 7)
DAYS_FIRST_RUN = 7
# Template pour l'export bulk (v2) - nécessite l'Auth-Key dans l'URL
BULK_EXPORT_URL_TEMPLATE = "https://threatfox-api.abuse.ch/v2/files/exports/{api_key}/full.json.zip"


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_existing_data() -> list:
    """Charge les IOCs déjà sauvegardés."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_json_atomic(data: list):
    """Sauvegarde la liste complète des IOCs en JSON de manière atomique."""
    tmp_file = OUTPUT_JSON + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, OUTPUT_JSON)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde JSON : {e}")

def load_tracking():
    """Charge le tracking JSON ou migre depuis l'ancien CSV."""
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    
    # Migration depuis l'ancien CSV
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            with open(OLD_TRACKING_FILE, "r", encoding="utf-8") as f:
                rows = list(csv.reader(f))
                data_rows = [r for r in rows if r and r[0] != "date_extraction"]
                if data_rows:
                    return {"latest_modified": data_rows[-1][0]}
        except:
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
        print(f"Erreur lors de la sauvegarde du tracking : {e}")


# Les anciennes fonctions CSV sont supprimées au profit des fonctions atomiques


def build_headers() -> dict:
    """Construit les en-têtes HTTP (auth si clé présente)."""
    headers = {"Content-Type": "application/json"}
    if API_KEY and API_KEY != "your_threatfox_api_key_here":
        headers["Auth-Key"] = API_KEY
    return headers


def fetch_iocs(days: int) -> list:
    """
    Interroge l'API ThreatFox pour obtenir les IOCs des N derniers jours.
    Retourne la liste brute d'IOCs ou [] en cas d'erreur.
    """
    payload = {"query": "get_iocs", "days": days}
    print(f"  → Requête ThreatFox : IOCs des {days} derniers jours...")
    try:
        response = requests.post(
            API_URL,
            headers=build_headers(),
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
    except Exception as e:
        print(f"  ✗ Erreur lors de la requête API : {e}")
        return []

    status = result.get("query_status", "")
    if status != "ok":
        print(f"  ✗ Statut API inattendu : {status}")
        # DEBUG: print full response if it fails
        print(f"  ✗ Raw response: {response.text}")
        return []

    data_iocs = result.get("data", [])
    if not data_iocs:
        print(f"  ✗ Attention, 0 données dans 'data'. Raw: {response.text[:200]}")
    return data_iocs or []


def fetch_bulk_iocs() -> list:
    """
    Télécharge et décompresse l'export complet JSON de ThreatFox (derniers 6 mois).
    """
    if not API_KEY or API_KEY == "your_threatfox_api_key_here":
        print("  ✗ Erreur : Clé API requise pour l'export bulk.")
        return []

    url = BULK_EXPORT_URL_TEMPLATE.format(api_key=API_KEY)
    print(f"  → Téléchargement de l'export complet (bulk ZIP)...")
    try:
        response = requests.get(url, timeout=300)
        if response.status_code != 200:
            print(f"  ✗ Erreur HTTP {response.status_code} lors du téléchargement bulk.")
            return []
            
        # Décompression du ZIP en mémoire
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            # On cherche le premier fichier .json dans le ZIP
            json_filename = [f for f in z.namelist() if f.endswith('.json')][0]
            with z.open(json_filename) as f:
                data_iocs = json.load(f)
                
    except Exception as e:
        print(f"  ✗ Erreur lors du téléchargement/décompression bulk : {e}")
        return []

    if isinstance(data_iocs, dict):
        # L'export bulk est un dictionnaire {id: [ioc_data]}
        # On doit injecter l'ID si absent de l'objet intérieur
        print(f"  → Dictionnaire détecté ({len(data_iocs)} entrées), mise à plat...")
        flattened = []
        for ioc_id, item_or_list in data_iocs.items():
            if isinstance(item_or_list, list):
                for subitem in item_or_list:
                    if isinstance(subitem, dict) and "id" not in subitem:
                        subitem["id"] = ioc_id
                    flattened.append(subitem)
            else:
                if isinstance(item_or_list, dict) and "id" not in item_or_list:
                    item_or_list["id"] = ioc_id
                flattened.append(item_or_list)
        return flattened

    if not isinstance(data_iocs, list):
        print(f"  ✗ Format inattendu pour l'export bulk (reçu {type(data_iocs)})")
        return []

    return data_iocs


def normalize_ioc(raw: dict) -> dict:
    """Normalise un IOC brut en un dictionnaire uniforme."""
    return {
        "id":            raw.get("id"),
        "ioc":           raw.get("ioc"),
        "ioc_type":      raw.get("ioc_type"),
        "ioc_type_desc": raw.get("ioc_type_desc"),
        "threat_type":   raw.get("threat_type"),
        "threat_type_desc": raw.get("threat_type_desc"),
        "malware":       raw.get("malware"),
        "malware_alias": raw.get("malware_alias"),
        "malware_printable": raw.get("malware_printable"),
        "confidence_level": raw.get("confidence_level"),
        "first_seen":    raw.get("first_seen"),
        "last_seen":     raw.get("last_seen"),
        "reporter":      raw.get("reporter"),
        "reference":     raw.get("reference"),
        "tags":          raw.get("tags"),
        "extracted_at":  datetime.now().isoformat(),
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    # Fix Windows encoding issues for arrow characters
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    print("=" * 60)
    print("ThreatFox IOC Extraction")
    print("=" * 60)

    if not API_KEY or API_KEY == "your_threatfox_api_key_here":
        print("[AVERTISSEMENT] Aucune clé API configurée dans .env")
        print("  Les requêtes publiques (sans auth) sont limitées.")

    # Arguments CLI
    is_full_sync = "--full" in sys.argv

    # Détermine combien de jours récupérer d'après le tracking
    existing   = load_existing_data()
    tracking   = load_tracking()
    tracking["last_sync_attempt"] = datetime.now().isoformat()
    
    last_run_str = tracking.get("last_run", tracking.get("latest_modified"))
    
    last_run = None
    if last_run_str:
        try:
            # Gestion de formats multiples (ISO ou YMD HMS)
            if "T" in last_run_str:
                last_run = datetime.fromisoformat(last_run_str.replace("Z", "+00:00")).replace(tzinfo=None)
            else:
                last_run = datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    if is_full_sync or last_run is None:
        is_full_sync = True
        print("  → Premier lancement ou mode --full : récupération de l'export complet (bulk)...")
        days = 0 
    else:
        delta = datetime.now() - last_run
        days  = max(1, delta.days + 1)
        print(f"  Dernière exécution (tracking) : {last_run_str}")
        print(f"  Intervalle : {delta.days} jour(s) → récupération des {days} derniers jours")

    print(f"\n[1/3] Chargement des données existantes : {len(existing)} IOCs")

    # Récupère les nouveaux IOCs
    print(f"\n[2/3] Extraction des IOCs...")
    if is_full_sync:
        raw_iocs = fetch_bulk_iocs()
    else:
        raw_iocs = fetch_iocs(days)
    print(f"  → {len(raw_iocs)} IOCs reçus.")

    if not raw_iocs:
        print("\nAucun IOC récupéré. Vérifiez votre clé API ou réessayez plus tard.")
        return

    # Fusion incrémentale
    print(f"\n[3/3] Fusion et dédoublonnage...")
    existing_ids = {item["id"] for item in existing if item.get("id")}
    new_entries = []

    for raw in raw_iocs:
        ioc_id = raw.get("id")
        if ioc_id not in existing_ids:
            new_entries.append(normalize_ioc(raw))
            existing_ids.add(ioc_id)

    if new_entries:
        existing.extend(new_entries)
        save_json_atomic(existing)
        print("\n" + "="*50)
        print(f"  ✓ {len(new_entries)} nouveaux IOCs ajoutés.")
        print("\nDétail des nouveaux IOC :")
        for item in new_entries:
            print(f" [+] {item['id']} ({item['ioc_type']}) - {item['threat_type']}")
        print("="*50)
        print(f"  ✓ Total en base : {len(existing)} IOCs")
    else:
        print(f"  ✓ Aucun nouvel IOC (tout est déjà en base).")

    # Calcul des dates min/max pour le tracking
    if existing:
        # first_seen est au format "YYYY-MM-DD HH:MM:SS"
        dates = [item.get("first_seen") for item in existing if item.get("first_seen")]
        if dates:
            tracking["earliest_modified"] = min(dates)
            tracking["latest_modified"] = max(dates)

    # Mise à jour du tracking
    now_str = datetime.now().isoformat()
    tracking["last_run"] = now_str
    tracking["last_sync_success"] = now_str
    save_tracking_atomic(tracking)
    
    # Nettoyage CSV final
    if os.path.exists(OLD_TRACKING_FILE):
        try: os.remove(OLD_TRACKING_FILE)
        except: pass
    
    print(f"\nDonnées sauvegardées dans : {OUTPUT_JSON}")
    print("=" * 60)


if __name__ == "__main__":
    main()
