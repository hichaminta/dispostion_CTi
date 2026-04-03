import json
import os
import threading
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

try:
    from OTXv2 import OTXv2
    from dotenv import load_dotenv, find_dotenv
except ImportError:
    print("Erreur : Bibliothèques manquantes. Installez OTXv2 et python-dotenv.")
    exit(1)

# =========================
# Configuration CTI / SOC
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "otx_pulses.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")

MAX_WORKERS = 10         # Threads pour l'enrichissement (IoCs)
SAVE_EVERY = 5           # Sauvegarde tous les 5 pulses (Flux continu)
PAGE_LIMIT = 200         # Taille de page API
MAX_PENDING_TASKS = 40   # Limite pour ne pas saturer la mémoire

load_dotenv(find_dotenv())

# Configuration fine du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

write_lock = threading.Lock()

# =========================
# Fonctions Utilitaires
# =========================

def get_api_key():
    return os.getenv("OTX_API_KEY")

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

def get_interval_from_data(data):
    """Calcule les bornes min/max des dates de modification du JSON."""
    if not data:
        return None, None
    dates = [p.get("modified") for p in data if p.get("modified")]
    if not dates:
        return None, None
    return min(dates), max(dates)

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
    """Sauvegarde atomique via .tmp + replace."""
    tmp_file = OUTPUT_JSON + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, OUTPUT_JSON)
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde JSON : {e}")

def fetch_pulse_indicators(otx, pulse):
    """Télécharger les indicateurs d'un pulse."""
    p_id = pulse.get("id")
    indicators = otx.get_pulse_indicators(p_id)
    
    return {
        "id": p_id,
        "name": pulse.get("name", "Sans nom"),
        "description": pulse.get("description", ""),
        "modified": pulse.get("modified"),
        "created": pulse.get("created"),
        "tags": pulse.get("tags", []),
        "references": pulse.get("references", []),
        "indicator_count": len(indicators),
        "indicators": indicators
    }

# =========================
# Logique de synchronisation
# =========================

def sync_pulses(otx, modified_since, existing_data, existing_ids, tracking, mode="AFTER"):
    """
    mode "AFTER" : Récupère les nouveautés depuis modified_since.
    mode "BEFORE" : Récupère l'historique (ignore tout ce qui est >= EARLIEST).
    """
    added_count = 0
    scanned_count = 0
    
    earliest_seen = tracking.get("earliest_modified")
    latest_seen = tracking.get("latest_modified")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        pulses_iter = otx.getall_iter(modified_since=modified_since, limit=PAGE_LIMIT)
        
        logging.info(f"Démarrage synchronisation [{mode}] (since={modified_since or 'Beginning'})...")

        for pulse in pulses_iter:
            scanned_count += 1
            p_id = pulse.get("id")
            p_mod = pulse.get("modified")

            # En mode BEFORE (Historique), on saute tout ce qu'on a déjà (intervalle connu)
            if mode == "BEFORE" and earliest_seen and p_mod >= earliest_seen:
                continue

            if p_id and p_id not in existing_ids:
                future = executor.submit(fetch_pulse_indicators, otx, pulse)
                futures[future] = pulse
            
            # Traitement des tâches terminées
            done_futures = [f for f in futures if f.done()]
            for f in done_futures:
                try:
                    result = f.result()
                    with write_lock:
                        existing_data.append(result)
                        existing_ids.add(result["id"])
                        added_count += 1
                        
                        # Mise à jour des bornes dynamiques
                        mod_date = result["modified"]
                        if not earliest_seen or mod_date < earliest_seen:
                            earliest_seen = mod_date
                        if not latest_seen or mod_date > latest_seen:
                            latest_seen = mod_date

                        if added_count % SAVE_EVERY == 0:
                            save_json_atomic(existing_data)
                            # On sauve aussi les bornes intermédiaires
                            tracking.update({
                                "earliest_modified": earliest_seen,
                                "latest_modified": latest_seen,
                                "last_sync_attempt": datetime.now(timezone.utc).isoformat()
                            })
                            save_tracking_atomic(tracking)
                    
                    logging.info(f"[+] Pulse '{result['name']}' enregistré")
                except Exception as e:
                    logging.error(f"Erreur Pulse : {e}")
                del futures[f]

            if len(futures) > MAX_PENDING_TASKS:
                wait(futures, return_when=FIRST_COMPLETED)

        # Attente des derniers threads
        for f in as_completed(futures):
            try:
                result = f.result()
                existing_data.append(result)
                existing_ids.add(result["id"])
                added_count += 1
                mod_date = result["modified"]
                if not earliest_seen or mod_date < earliest_seen:
                    earliest_seen = mod_date
                if not latest_seen or mod_date > latest_seen:
                    latest_seen = mod_date
            except Exception as e:
                logging.error(f"Erreur Pulse final : {e}")

    # Mise à jour finale du tracking pour cette phase
    tracking.update({
        "earliest_modified": earliest_seen,
        "latest_modified": latest_seen,
        "last_sync_success": datetime.now(timezone.utc).isoformat()
    })
    save_tracking_atomic(tracking)
    save_json_atomic(existing_data)
    
    return scanned_count, added_count

def main():
    api_key = get_api_key()
    if not api_key:
        logging.error("Clé API absente du fichier .env")
        return

    otx = OTXv2(api_key)
    
    # 1. Charger les pulses existants
    existing_data = load_existing_data()
    existing_ids = {p["id"] for p in existing_data if "id" in p}
    logging.info(f"Indexation : {len(existing_ids)} pulses chargés localement.")

    # 2. Charger le tracking ou calculer l'intervalle depuis le JSON
    tracking = load_tracking()
    e_calc, l_calc = get_interval_from_data(existing_data)
    
    if "earliest_modified" not in tracking:
        tracking["earliest_modified"] = e_calc
    if "latest_modified" not in tracking:
        tracking["latest_modified"] = l_calc
    
    logging.info(f"Intervalle actuel : {tracking.get('earliest_modified')} <-> {tracking.get('latest_modified')}")

    try:
        # PHASE 1 : Nouveautés (FUTUR)
        # On part du plus récent pour aller vers maintenant
        logging.info("--- PHASE 1 : Récupération des nouveautés ---")
        sc_1, ad_1 = sync_pulses(otx, tracking.get("latest_modified"), existing_data, existing_ids, tracking, mode="AFTER")
        logging.info(f"Bilan Nouveautés : {sc_1} scannés, {ad_1} ajoutés.")

        # PHASE 2 : Historique (PASSÉ)
        # On repart de ZERO et on descend jusqu'à ce qu'on dépasse le plus ancien
        # Pour simplifier, on peut l'activer via une question ou le faire systématiquement
        logging.info("--- PHASE 2 : Complétion de l'historique ---")
        sc_2, ad_2 = sync_pulses(otx, None, existing_data, existing_ids, tracking, mode="BEFORE")
        logging.info(f"Bilan Historique : {sc_2} scannés, {ad_2} ajoutés.")

        logging.info("Toutes les phases de synchronisation sont terminées.")

    except KeyboardInterrupt:
        logging.warning("\nInterruption détectée. Les données et le tracking ont été sauvés.")
    except Exception as e:
        logging.error(f"Erreur critique : {e}")

if __name__ == "__main__":
    main()