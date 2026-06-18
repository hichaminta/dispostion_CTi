import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import os
import json
import requests
import logging
from dotenv import load_dotenv, find_dotenv

# Setup logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Enrichment_AbuseIPDB")

# Configuration
load_dotenv(find_dotenv())
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

# ── Local DB path: check in enrichment_ip/ first, then legacy Sources_data/
_local_db_primary = os.path.join(os.path.dirname(__file__), "abuseipdb_data.json")
_local_db_legacy   = os.path.join(BASE_DIR, "Sources_data", "AbuseIPDB", "abuseipdb_data.json")
DB_PATH = _local_db_primary if os.path.exists(_local_db_primary) else _local_db_legacy


class AbuseIPDBEnricher:
    """Enriches IPs using a local JSON database FIRST, then falls back to API."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.local_db = self._load_db()
        self.new_data_count = 0

    # ── Private helpers ────────────────────────────────────────────────────────

    def _load_db(self):
        """Load the local JSON database into a dict keyed by IP address."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    db = {item["ipAddress"]: item for item in data if "ipAddress" in item}
                    logger.info(f"[LOCAL DB] Loaded {len(db)} IPs from {self.db_path}")
                    return db
            except Exception as e:
                logger.error(f"Failed to load local DB: {e}")
        else:
            logger.warning(f"[LOCAL DB] Not found at {self.db_path} — starting fresh.")
        return {}

    def _save_db(self):
        """Persist the updated local database back to disk."""
        if self.new_data_count > 0:
            try:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
                with open(self.db_path, "w", encoding="utf-8") as f:
                    json.dump(list(self.local_db.values()), f, indent=4)
                logger.info(f"[LOCAL DB] Updated with {self.new_data_count} new API entries.")
            except Exception as e:
                logger.error(f"Failed to save local DB: {e}")

    def _query_api(self, ip):
        """Call AbuseIPDB API only when the IP is absent from the local DB."""
        if not API_KEY:
            logger.warning("[API] ABUSEIPDB_API_KEY not set — API calls disabled.")
            return None
        logger.info(f"  [API] Querying AbuseIPDB for {ip} (not in local DB)...")
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": API_KEY, "Accept": "application/json"}
            params  = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                if data:
                    # Save into local DB so the next run won't call the API again
                    self.local_db[ip] = data
                    self.new_data_count += 1
                    return data
            else:
                logger.warning(f"  [API] HTTP {response.status_code} for {ip}")
        except Exception as e:
            logger.error(f"  [API] Error for {ip}: {e}")
        return None

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_ip_info(self, ip):
        """Return AbuseIPDB info for an IP.
        
        Priority:
          1. Local DB (no API call).
          2. AbuseIPDB API (result stored in local DB for future runs).
        """
        if ip in self.local_db:
            logger.debug(f"  [LOCAL] {ip} found in local DB — skipping API call.")
            return self.local_db[ip]

        return self._query_api(ip)

    def run(self):
        """Iterate over all enriched files and enrich IP-type IOCs."""
        if not os.path.exists(ENRICHMENT_DIR):
            logger.error(f"Enrichment directory not found: {ENRICHMENT_DIR}")
            return

        files = [f for f in os.listdir(ENRICHMENT_DIR) if f.endswith("_enriched.json")]
        if not files:
            logger.warning("[AbuseIPDB] No *_enriched.json files found. Skipping.")
            return

        logger.info(f"[AbuseIPDB] Processing {len(files)} enriched file(s)...")

        for filename in files:
            filepath = os.path.join(ENRICHMENT_DIR, filename)
            modified = False

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception as e:
                logger.error(f"Cannot read {filename}: {e}")
                continue

            for record in records:
                for ioc in record.get("iocs", []):
                    if ioc.get("type") != "ip":
                        continue

                    enrichment = ioc.setdefault("ioc_enrichment", {})

                    # ── Skip: already processed by AbuseIPDB ──────────────
                    if enrichment.get("passer_par_abuseipdb") == 1:
                        logger.debug(f"  [SKIP] {ioc.get('value')} already enriched (passer_par_abuseipdb=1).")
                        continue

                    raw_ip = ioc.get("value")
                    if not raw_ip:
                        continue

                    # ── Nettoyage de l'IP ─────────────────────────────────────
                    # Retirer le port s'il est présent (ex: 42.225.207.134:34110)
                    clean_ip = raw_ip.split(":")[0]

                    # Ignorer les blocs CIDR (ex: 1.10.16.0/20) non supportés par l'endpoint /check
                    if "/" in clean_ip:
                        logger.debug(f"  [SKIP] {raw_ip} est un bloc CIDR, ignoré pour AbuseIPDB.")
                        continue

                    info = self.get_ip_info(clean_ip)
                    if info:
                        enrichment.update({
                            "abuseConfidenceScore": info.get("abuseConfidenceScore"),
                            "totalReports":         info.get("totalReports"),
                            "lastReportedAt":       info.get("lastReportedAt"),
                            "countryCode":          info.get("countryCode"),
                            "isp":                  info.get("isp"),
                            "source_reliability":   "AbuseIPDB Local/API",
                            # ── Tracking flag ──────────────────────────────
                            "passer_par_abuseipdb": 1,
                        })
                        modified = True
                        source = "LOCAL DB" if clean_ip in self.local_db else "API"
                        logger.info(f"  [OK] {clean_ip} enriched via {source} (score={info.get('abuseConfidenceScore')})")

            if modified:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=4)
                logger.info(f"[SAVED] {filename}")

        self._save_db()
        logger.info("[AbuseIPDB] Enrichment stage complete.")


if __name__ == "__main__":
    enricher = AbuseIPDBEnricher(DB_PATH)
    enricher.run()
