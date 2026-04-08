"""
PhishTank — Script d'extraction CTI
Stratégie multi-source :
  1. PhishTank officiel (si PHISHTANK_API_KEY est défini dans .env)
  2. OpenPhish (feed CSV public gratuit) — fallback 1
  3. URLhaus (API JSON gratuite, focus malware/phishing) — fallback 2
"""

import requests
import json
import os
import sys
import io
import csv
import subprocess
import logging
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

# ── Configuration ───────────────────────────────────────────────────────────
load_dotenv(find_dotenv(), override=False)
API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON      = os.path.join(SCRIPT_DIR, "phishtank_data.json")
TRACKING_FILE    = os.path.join(SCRIPT_DIR, "tracking.json")
today_str        = datetime.now().strftime("%Y-%m-%d")
DAILY_JSON       = os.path.join(SCRIPT_DIR, f"phishtank_data_{today_str}.json")

SAVE_EVERY   = 500
TIMEOUT      = 90

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)

write_lock = threading.Lock()

# ── Sources ─────────────────────────────────────────────────────────────────
PHISHTANK_URL_AUTH  = f"http://data.phishtank.com/data/{API_KEY}/online-valid.json"
PHISHTANK_URL_ANON  = "http://data.phishtank.com/data/online-valid.json"
OPENPHISH_URL       = "https://openphish.com/feed.txt"
URLHAUS_API         = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# ── Tracking / IO helpers ────────────────────────────────────────────────────
def load_tracking():
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_tracking(tracking):
    tmp = TRACKING_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(tracking, f, indent=4, ensure_ascii=False)
        os.replace(tmp, TRACKING_FILE)
    except Exception as e:
        logging.error(f"Erreur tracking : {e}")

def load_existing():
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, list) else []
        except Exception:
            pass
    return []

def save_json(data, path=None):
    target = path or OUTPUT_JSON
    tmp = target + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, target)
    except Exception as e:
        logging.error(f"Erreur sauvegarde ({target}) : {e}")

# ── Source 1 : PhishTank officiel ────────────────────────────────────────────
def fetch_phishtank_official():
    """Utilise la clé API si disponible, sinon tente l'accès anonyme."""
    if not API_KEY:
        url = PHISHTANK_URL_ANON
        headers = {
            "User-Agent": "CTI-Pipeline/1.0 (research)",
            "Accept": "application/json",
        }
        logging.info("[PhishTank] Pas de clé API — tentative par l'accès anonyme (rate limit possible)...")
    else:
        url = PHISHTANK_URL_AUTH
        headers = {
            "User-Agent": f"phishtank/{API_KEY}",
            "Accept": "application/json",
        }
        logging.info("[PhishTank] Téléchargement officiel (avec clé)...")
        
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        raw = r.json()
        if isinstance(raw, list):
            logging.info(f"[PhishTank] {len(raw)} entrées récupérées.")
            return raw
        logging.warning(f"[PhishTank] Format inattendu : {type(raw)}")
    except Exception as e:
        logging.error(f"[PhishTank] Erreur : {e}")
    return []

def normalize_phishtank(item):
    """Normalise un enregistrement PhishTank vers le schéma unifié."""
    collected_at = datetime.now(timezone.utc).isoformat()
    submission_time = item.get("submission_time", "")
    
    return {
        "phish_id":         str(item.get("phish_id", "")),
        "ioc":              item.get("url", ""),
        "source":           "PhishTank",
        "type":             "url-phishing",
        "target":           item.get("target", ""),
        "verified":         item.get("verified", "yes"),
        "online":           item.get("online", "yes"),
        "submission_time":  submission_time,
        "verification_time":item.get("verification_time", ""),
        "phish_detail_url": item.get("phish_detail_url", ""),
        "collected_at":     collected_at,
        "date":             submission_time if submission_time else collected_at,
        # Inclure tous les champs supplémentaires éventuels (EXTRAIT TOUT)
        **{k: v for k, v in item.items() if k not in ["url", "submission_time"]}
    }

# ── Source 2 : OpenPhish ─────────────────────────────────────────────────────
def fetch_openphish():
    """
    OpenPhish fournit un feed texte gratuit : une URL par ligne.
    URL : https://openphish.com/feed.txt
    """
    logging.info("[OpenPhish] Téléchargement du feed gratuit...")
    try:
        r = requests.get(
            OPENPHISH_URL,
            headers={"User-Agent": "CTI-Pipeline/1.0 (research)"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        lines = [l.strip() for l in r.text.splitlines() if l.strip().startswith("http")]
        logging.info(f"[OpenPhish] {len(lines)} URLs récupérées.")
        return lines
    except Exception as e:
        logging.error(f"[OpenPhish] Erreur : {e}")
        return []

def normalize_openphish(url):
    collected_at = datetime.now(timezone.utc).isoformat()
    return {
        "phish_id":         None,
        "ioc":              url,
        "source":           "OpenPhish",
        "type":             "url-phishing",
        "target":           "",
        "verified":         "community",
        "online":           "yes",
        "submission_time":  None,
        "verification_time":"",
        "phish_detail_url": "",
        "collected_at":     collected_at,
        "date":             collected_at, # Fallback date de collection
    }

# ── Source 3 : URLhaus (abuse.ch) ────────────────────────────────────────────
def fetch_urlhaus():
    """
    URLhaus API — liste des URL malveillantes récentes (gratuit, sans clé).
    POST https://urlhaus-api.abuse.ch/v1/urls/recent/
    """
    logging.info("[URLhaus] Téléchargement des URL récentes...")
    try:
        r = requests.post(
            URLHAUS_API,
            headers={"User-Agent": "CTI-Pipeline/1.0 (research)"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "is_available" and isinstance(data.get("urls"), list):
            logging.info(f"[URLhaus] {len(data['urls'])} URLs récupérées.")
            return data["urls"]
        logging.warning(f"[URLhaus] Réponse inattendue : {data.get('query_status')}")
    except Exception as e:
        logging.error(f"[URLhaus] Erreur : {e}")
    return []

def normalize_urlhaus(item):
    collected_at = datetime.now(timezone.utc).isoformat()
    date_added = item.get("date_added", "")
    
    return {
        "phish_id":         item.get("id", ""),
        "ioc":              item.get("url", ""),
        "source":           "URLhaus",
        "type":             item.get("threat", "url-malware"),
        "target":           "",
        "verified":         "yes",
        "online":           item.get("url_status", ""),
        "submission_time":  date_added,
        "verification_time":"",
        "phish_detail_url": item.get("urlhaus_link", ""),
        "collected_at":     collected_at,
        "date":             date_added if date_added else collected_at,
        # Extractions additionnelles URLhaus
        "reporter":         item.get("reporter", ""),
        "threat":           item.get("threat", ""),
        "tags":             item.get("tags", []),
        "last_online":      item.get("last_online", ""),
        **{k: v for k, v in item.items() if k not in ["url", "id", "date_added", "urlhaus_link", "url_status", "threat"]}
    }

# ── Merge logic ───────────────────────────────────────────────────────────────
def merge_records(existing_data, new_items, tracking, new_records_out):
    """
    Fusionne les nouveaux items dans existing_data en évitant les doublons via l'IOC.
    """
    existing_iocs = {item.get("ioc", ""): item for item in existing_data if item.get("ioc")}
    added = 0
    earliest = tracking.get("earliest_modified")
    latest   = tracking.get("latest_modified")
    total    = len(new_items)

    for i, item in enumerate(new_items, 1):
        ioc = item.get("ioc", "")
        if not ioc:
            continue
        
        if ioc in existing_iocs:
            # Mise à jour des données existantes
            old_item = existing_iocs[ioc]
            old_item.update({
                "online": item.get("online"),
                "verified": item.get("verified"),
                "collected_at": item.get("collected_at"),
            })
            # On peut aussi mettre à jour d'autres champs si présents
            for k, v in item.items():
                if k not in old_item or old_item[k] is None:
                    old_item[k] = v
                    
            new_records_out.append(old_item)
            added += 1
            continue

        print(f"  [{i}/{total}] Nouveau : {ioc[:80]}", end="\r", flush=True)
        existing_data.append(item)
        existing_iocs.add(ioc)
        new_records_out.append(item)
        added += 1

        # Utiliser le champ 'date' unifié pour le tracking
        item_date = item.get("date", "")
        if item_date:
            if not earliest or item_date < earliest:
                earliest = item_date
            if not latest   or item_date > latest:
                latest   = item_date

        if added > 0 and added % SAVE_EVERY == 0:
            save_json(existing_data)
            tracking.update({"earliest_modified": earliest, "latest_modified": latest,
                             "last_sync_attempt": datetime.now(timezone.utc).isoformat()})
            save_tracking(tracking)

    print()
    return added, earliest, latest

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        try:
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    logging.info("=" * 55)
    logging.info("  Extraction PhishTank/OpenPhish/URLhaus")
    logging.info("=" * 55)

    existing_data = load_existing()
    tracking      = load_tracking()
    logging.info(f"Indexation : {len(existing_data)} phishings chargés.")

    # ── Étape 1 : PhishTank officiel (si clé disponible)
    normalized_items = []
    source_used = []

    pt_raw = fetch_phishtank_official()
    if pt_raw:
        normalized_items += [normalize_phishtank(r) for r in pt_raw]
        source_used.append("PhishTank")

    # ── Étape 2 : OpenPhish (fallback / complément gratuit)
    op_urls = fetch_openphish()
    if op_urls:
        normalized_items += [normalize_openphish(u) for u in op_urls]
        source_used.append("OpenPhish")

    # ── Étape 3 : URLhaus (si les deux précédents ont échoué ou pour enrichir)
    if not normalized_items:
        logging.warning("PhishTank et OpenPhish indisponibles — tentative URLhaus...")
        uh_raw = fetch_urlhaus()
        if uh_raw:
            normalized_items += [normalize_urlhaus(r) for r in uh_raw]
            source_used.append("URLhaus")

    if not normalized_items:
        logging.error("Aucune source disponible. Arrêt.")
        tracking["last_run"] = datetime.now(timezone.utc).isoformat()
        save_tracking(tracking)
        return

    logging.info(f"Total entrées à traiter : {len(normalized_items)} ({', '.join(source_used)})")

    # ── Fusion dans le fichier cumulatif
    new_records = []
    added, earliest, latest = merge_records(existing_data, normalized_items, tracking, new_records)

    # ── Finalisation
    now = datetime.now(timezone.utc).isoformat()
    
    tracking["last_run"] = now

    if added > 0:
        tracking.update({
            "last_sync_success": now,
            "earliest_modified": earliest,
            "latest_modified":   latest,
            "total_collected":   len(existing_data),
            "sources_used":      source_used,
        })
        save_json(existing_data)
    else:
        logging.info("Aucune nouvelle URL, les dates de synchronisation et les données existantes ne sont pas modifiées.")

    save_tracking(tracking)

    if new_records:
        logging.info(f"Export journalier : {len(new_records)} nouveaux items → {os.path.basename(DAILY_JSON)}")
        save_json(new_records, DAILY_JSON)

    logging.info("=" * 55)
    logging.info(f"  Sources utilisées : {', '.join(source_used)}")
    logging.info("=" * 55)

    # [AUTOMATION] Extraction directe des IOCs/CVEs après collecte
    extraction_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'extraction_ioc_cve'))
    extractor_script = os.path.join(extraction_dir, "phishtank_extractor.py")
    if os.path.exists(extractor_script):
        logging.info(">>> AUTOMATION : Lancement de l'extraction (phishtank_extractor.py)...")
        subprocess.run([sys.executable, extractor_script], cwd=extraction_dir)
    else:
        logging.warning(f">>> Extracteur non trouvé : {extractor_script}")


if __name__ == "__main__":
    main()
