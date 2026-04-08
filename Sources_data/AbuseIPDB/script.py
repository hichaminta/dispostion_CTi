import os
import json
import requests
import logging
import sys
from datetime import datetime, timezone
import subprocess
from dotenv import load_dotenv, find_dotenv

# ── Configuration du logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ── Configuration et Chargement ──────────────────────────────────────────────
load_dotenv(find_dotenv())
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_KEY:
    logging.error("ABUSEIPDB_API_KEY introuvable dans le fichier .env")
    sys.exit(1)

BASE_URL = "https://api.abuseipdb.com/api/v2"
HEADERS = {
    "Key": API_KEY,
    "Accept": "application/json",
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "abuseipdb_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

# Daily export configuration
today_str = datetime.now().strftime("%Y-%m-%d")
DAILY_OUTPUT_JSON = os.path.join(SCRIPT_DIR, f"abuseipdb_data_{today_str}.json")

# ── Fonctions Utilitaires ────────────────────────────────────────────────────

def load_tracking():
    """Charge l'état du dernier scan."""
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Impossible de lire le tracking JSON : {e}")
    return {}

def save_tracking_atomic(tracking):
    """Sauvegarde l'état du scan de manière sécurisée."""
    tmp_file = TRACKING_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(tracking, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, TRACKING_FILE)
    except Exception as e:
        logging.error(f"Erreur tracking : {e}")

def load_existing_data():
    """Charge les données existantes de la base locale."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            pass
    return []

def save_json_atomic(data, filepath=None):
    """Sauvegarde les données JSON (Master ou Daily) de manière atomique."""
    target_file = filepath if filepath else OUTPUT_JSON
    tmp_file = target_file + ".tmp"
    try:
        # S'assurer que le dossier existe (pour le daily export)
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, target_file)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON ({target_file}) : {e}")

# ── Fonctions API AbuseIPDB ──────────────────────────────────────────────────

def check_ip(ip: str, max_age_in_days: int = 90, verbose: bool = True) -> dict:
    """Vérifie un IP et retourne son rapport complet."""
    url = f"{BASE_URL}/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_in_days,
        "verbose": verbose,
    }
    try:
        response = requests.get(url, headers=HEADERS, params=params)
        response.raise_for_status()
        return response.json().get("data", {})
    except Exception as e:
        logging.error(f"Erreur check_ip pour {ip}: {e}")
    return None

def get_blacklist(confidence_minimum: int = 90, limit: int = 10000) -> list:
    """Récupère la blacklist AbuseIPDB."""
    url = f"{BASE_URL}/blacklist"
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit,
    }
    try:
        response = requests.get(url, headers=HEADERS, params=params)
        response.raise_for_status()
        return response.json().get("data", [])
    except Exception as e:
        logging.error(f"Erreur get_blacklist: {e}")
    return []

# ── Logique de Synchronisation Principale ────────────────────────────────────

def sync_data(blacklist_data, existing_data, tracking):
    """
    Synchronise les données de la blacklist avec la base locale.
    Utilise le 'tracking' pour éviter de traiter les anciennes données.
    """
    existing_ips = {item["ipAddress"]: item for item in existing_data if "ipAddress" in item}
    new_entries_daily = []
    
    last_run_iso = tracking.get("latest_reported_at")
    last_run_dt = None
    if last_run_iso:
        try:
            last_run_dt = datetime.fromisoformat(last_run_iso.replace("Z", "+00:00"))
        except: pass

    current_latest_reported = last_run_iso
    current_latest_dt = last_run_dt

    added_count = 0
    updated_count = 0
    total_to_process = len(blacklist_data)

    logging.info(f"Analyse de {total_to_process} IPs de la blacklist...")

    for i, entry in enumerate(blacklist_data, 1):
        ip_addr = entry.get("ipAddress")
        score = entry.get("abuseConfidenceScore")
        last_reported_str = entry.get("lastReportedAt")
        
        if not ip_addr:
            continue

        # Vérification temporelle (Incrémental)
        last_reported_dt = None
        if last_reported_str:
            try:
                last_reported_dt = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
            except: pass

        # Si le rapport est plus ancien que notre dernière synchronisation, on ignore
        if last_run_dt and last_reported_dt and last_reported_dt <= last_run_dt:
            continue

        # Mise à jour des bornes de tracking
        if last_reported_dt:
            if not current_latest_dt or last_reported_dt > current_latest_dt:
                current_latest_dt = last_reported_dt
                current_latest_reported = last_reported_str

        # Affichage progression
        print(f"[{i}/{total_to_process}] Vérification: {ip_addr}", end="\r")
        sys.stdout.flush()

        if ip_addr in existing_ips:
            # Mise à jour des données existantes (scores, dates)
            old_item = existing_ips[ip_addr]
            old_item["abuseConfidenceScore"] = score
            old_item["lastReportedAt"] = last_reported_str
            old_item["extracted_at"] = datetime.now(timezone.utc).isoformat()
            
            # On considère aussi les mises à jour comme pertinentes pour l'export journalier
            new_entries_daily.append(old_item)
            updated_count += 1
            continue
        else:
            # Nouveauté : Création d'une nouvelle entrée
            new_item = {
                "ipAddress": ip_addr,
                "abuseConfidenceScore": score,
                "lastReportedAt": last_reported_str,
                "extracted_at": datetime.now(timezone.utc).isoformat()
            }
            existing_data.append(new_item)
            existing_ips[ip_addr] = new_item
            new_entries_daily.append(new_item)
            added_count += 1

    print("\n")
    logging.info(f"Synchronisation terminée : {added_count} nouveaux, {updated_count} mis à jour.")
    
    # Mise à jour du tracking final
    tracking["latest_reported_at"] = current_latest_reported
    tracking["last_run"] = datetime.now(timezone.utc).isoformat()
    
    return new_entries_daily

# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    try:
        # 1. Charger données et tracking
        existing_data = load_existing_data()
        tracking = load_tracking()
        logging.info(f"Base locale : {len(existing_data)} IPs.")

        # 2. Récupérer la Blacklist complète (configurée à 10000 par défaut)
        logging.info("Récupération de la Blacklist AbuseIPDB...")
        blacklist = get_blacklist(confidence_minimum=90, limit=10000)
        
        if not blacklist:
            logging.warning("Aucune donnée reçue de la blacklist.")
            return

        # 3. Synchronisation
        new_entries = sync_data(blacklist, existing_data, tracking)

        # 4. Sauvegardes
        save_json_atomic(existing_data)
        save_tracking_atomic(tracking)

        if new_entries:
            # Gestion de l'export journalier (Ajout si le fichier existe déjà aujourd'hui)
            final_daily_data = new_entries
            if os.path.exists(DAILY_OUTPUT_JSON):
                try:
                    with open(DAILY_OUTPUT_JSON, "r", encoding="utf-8") as f:
                        old_daily = json.load(f)
                        if isinstance(old_daily, list):
                            # Éviter les doublons si on relance le script
                            existing_daily_ips = {item["ipAddress"] for item in old_daily if "ipAddress" in item}
                            for entry in new_entries:
                                if entry["ipAddress"] not in existing_daily_ips:
                                    old_daily.append(entry)
                            final_daily_data = old_daily
                except Exception as e:
                    logging.warning(f"Impossible de fusionner l'export journalier : {e}")
            
            logging.info(f"Export journalier : {len(final_daily_data)} entrées au total pour aujourd'hui.")
            save_json_atomic(final_daily_data, DAILY_OUTPUT_JSON)
        else:
            logging.info("Aucune nouvelle IP à ajouter aujourd'hui.")

    except KeyboardInterrupt:
        logging.warning("Interruption par l'utilisateur. Sauvegarde en cours...")
        # Note : save_json_atomic est déjà appelé régulièrement dans certains pipelines, 
        # ici on s'assure d'un état cohérent.
        sys.exit(0)
    except Exception as e:
        logging.error(f"Une erreur inattendue est survenue : {e}")

    # [AUTOMATION] Extraction directe des IOCs/CVEs après collecte
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "abuseipdb_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (abuseipdb_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")

if __name__ == "__main__":
    main()