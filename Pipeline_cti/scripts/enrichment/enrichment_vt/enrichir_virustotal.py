import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
"""
enrichir_virustotal.py
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Enrichit les IOCs de type url / domain / hash avec VirusTotal.

Logique (identique Ã  AbuseIPDB) :
  1. Consulte la base locale  virustotal_data.json  en PREMIER.
  2. Si trouvÃ© â†’ utilise les donnÃ©es locales, zÃ©ro appel API.
  3. Si absent â†’ appelle l'API VirusTotal, stocke le rÃ©sultat dans
     la base locale pour les prochains runs.
  4. Pose le flag  passer_par_virustotal = 1  sur l'IOC traitÃ©.
  5. Skip les IOCs qui ont dÃ©jÃ   passer_par_virustotal = 1.

# Types ciblÃ©s : url, domain, domaine, hash, md5, sha1, sha256, sha512, ip, ipv4.
# Les IPs sont dÃ©sormais Ã©galement gÃ©rÃ©es par VirusTotal.
"""

import os
import json
import time
import base64
import logging
import requests
from dotenv import load_dotenv, find_dotenv

# â”€â”€ Logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Enrichment_VirusTotal")

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
load_dotenv(find_dotenv())
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_DIR           = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "sources")
DB_PATH            = os.path.join(os.path.dirname(__file__), "virustotal_data.json")

VT_API_BASE    = "https://www.virustotal.com/api/v3"
API_DELAY_SEC  = 15   # Free tier: 4 req/min â†’ wait 15 s between calls

# IOC types that VirusTotal can analyse
VT_TARGET_TYPES = {"url", "domain", "domaine", "hash", "hashe", "md5", "sha1", "sha256", "sha512", "ip", "ipv4"}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class VirusTotalEnricher:
    """Local-first VirusTotal enricher for urls, domains, and file hashes."""

    def __init__(self, db_path: str):
        self.db_path       = db_path
        self.local_db      = self._load_db()   # { value: vt_result_dict }
        self.new_data_count = 0
        self._api_calls     = 0

    # â”€â”€ DB helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _load_db(self) -> dict:
        """Load the local JSON database into a dict keyed by IOC value."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    # Support both list format and dict format
                    if isinstance(raw, list):
                        db = {entry["value"]: entry for entry in raw if "value" in entry}
                    else:
                        db = raw
                    logger.info(f"[LOCAL DB] Loaded {len(db)} VirusTotal entries from {self.db_path}")
                    return db
            except Exception as e:
                logger.error(f"[LOCAL DB] Failed to load: {e}")
        else:
            logger.warning(f"[LOCAL DB] Not found at {self.db_path} â€” starting fresh.")
        return {}

    def _save_db(self):
        """Persist the updated local database to disk."""
        if self.new_data_count > 0:
            try:
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
                with open(self.db_path, "w", encoding="utf-8") as f:
                    json.dump(list(self.local_db.values()), f, indent=4)
                logger.info(f"[LOCAL DB] Saved â€” {self.new_data_count} new entry(ies) added.")
            except Exception as e:
                logger.error(f"[LOCAL DB] Failed to save: {e}")

    # â”€â”€ API helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _headers(self) -> dict:
        return {"x-apikey": API_KEY, "Accept": "application/json"}

    def _extract_stats(self, attributes: dict) -> dict:
        """Extract the useful fields from a VT attributes object."""
        stats = attributes.get("last_analysis_stats", {})
        return {
            "vt_malicious_count":   stats.get("malicious", 0),
            "vt_suspicious_count":  stats.get("suspicious", 0),
            "vt_harmless_count":    stats.get("harmless", 0),
            "vt_total_engines":     sum(stats.values()) if stats else 0,
            "vt_reputation":        attributes.get("reputation", None),
            "vt_tags":              attributes.get("tags", []),
            "vt_last_analysis_date": attributes.get("last_analysis_date", None),
            "vt_permalink":         attributes.get("link", None),
        }

    def _query_url(self, url: str) -> dict | None:
        """Query VirusTotal for a URL."""
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            r = requests.get(f"{VT_API_BASE}/urls/{url_id}", headers=self._headers(), timeout=15)
            if r.status_code == 200:
                return self._extract_stats(r.json().get("data", {}).get("attributes", {}))
            elif r.status_code == 404:
                # Submit for scanning then return None (result available next run)
                logger.info(f"  [API-URL] {url[:40]}... not in VT yet, submitting for scan.")
                requests.post(f"{VT_API_BASE}/urls", headers=self._headers(),
                              data={"url": url}, timeout=15)
            else:
                logger.warning(f"  [API-URL] HTTP {r.status_code} for {url[:40]}")
        except Exception as e:
            logger.error(f"  [API-URL] Error: {e}")
        return None

    def _query_domain(self, domain: str) -> dict | None:
        """Query VirusTotal for a domain."""
        # Strip protocol if present
        if "://" in domain:
            from urllib.parse import urlparse
            domain = urlparse(domain).hostname or domain
        try:
            r = requests.get(f"{VT_API_BASE}/domains/{domain}", headers=self._headers(), timeout=15)
            if r.status_code == 200:
                return self._extract_stats(r.json().get("data", {}).get("attributes", {}))
            else:
                logger.warning(f"  [API-DOMAIN] HTTP {r.status_code} for {domain}")
        except Exception as e:
            logger.error(f"  [API-DOMAIN] Error: {e}")
        return None

    def _query_ip(self, ip: str) -> dict | None:
        """Query VirusTotal for an IP address."""
        try:
            r = requests.get(f"{VT_API_BASE}/ip_addresses/{ip}", headers=self._headers(), timeout=15)
            if r.status_code == 200:
                return self._extract_stats(r.json().get("data", {}).get("attributes", {}))
            else:
                logger.warning(f"  [API-IP] HTTP {r.status_code} for {ip}")
        except Exception as e:
            logger.error(f"  [API-IP] Error: {e}")
        return None

    def _query_hash(self, file_hash: str) -> dict | None:
        """Query VirusTotal for a file hash (md5/sha1/sha256/sha512)."""
        try:
            r = requests.get(f"{VT_API_BASE}/files/{file_hash}", headers=self._headers(), timeout=15)
            if r.status_code == 200:
                return self._extract_stats(r.json().get("data", {}).get("attributes", {}))
            else:
                logger.warning(f"  [API-HASH] HTTP {r.status_code} for {file_hash[:20]}...")
        except Exception as e:
            logger.error(f"  [API-HASH] Error: {e}")
        return None

    def _call_api(self, ioc_value: str, ioc_type: str) -> dict | None:
        """Route to the correct API endpoint based on IOC type."""
        if not API_KEY:
            logger.warning("[API] VIRUSTOTAL_API_KEY not set â€” API calls disabled.")
            return None

        logger.info(f"  [API] Querying VT for {ioc_type}: {ioc_value[:50]}")

        if ioc_type == "url":
            result = self._query_url(ioc_value)
        elif ioc_type in ("domain", "domaine"):
            result = self._query_domain(ioc_value)
        elif ioc_type in ("hash", "hashe", "md5", "sha1", "sha256", "sha512"):
            result = self._query_hash(ioc_value)
        elif ioc_type in ("ip", "ipv4"):
            result = self._query_ip(ioc_value)
        else:
            return None

        if result:
            # Store in local DB for future runs
            entry = {"value": ioc_value, "type": ioc_type, **result}
            self.local_db[ioc_value] = entry
            self.new_data_count += 1
            self._api_calls += 1
            # Respect API rate limit (free: 4 req/min)
            time.sleep(API_DELAY_SEC)

        return result

    # â”€â”€ Main logic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get_vt_info(self, ioc_value: str, ioc_type: str) -> dict | None:
        """Return VT data for an IOC â€” local DB first, then API fallback."""
        if ioc_value in self.local_db:
            logger.debug(f"  [LOCAL] {ioc_value[:50]} found in local DB â€” skipping API.")
            return self.local_db[ioc_value]
        return self._call_api(ioc_value, ioc_type)

    def run(self):
        """Iterate over all enriched files and enrich VT-compatible IOCs."""
        import glob
        pattern = os.path.join(GLOBAL_SOURCES_DIR, "*", "enrichment", "*_enriched.json")
        all_files = glob.glob(pattern)
        if not all_files:
            logger.warning("[VT] No *_enriched.json files found. Skipping.")
            return

        logger.info(f"[VT] Processing {len(all_files)} enriched file(s)...")
        total_enriched = 0

        for filepath in all_files:
            filename = os.path.basename(filepath)
            modified = False

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception as e:
                logger.error(f"Cannot read {filename}: {e}")
                continue

            for record in records:
                for ioc in record.get("iocs", []):
                    ioc_type  = ioc.get("type", "").lower()
                    ioc_value = ioc.get("value", "")

                    if ioc_type not in VT_TARGET_TYPES or not ioc_value:
                        continue

                    enrichment = ioc.setdefault("ioc_enrichment", {})

                    # â”€â”€ Skip: already processed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                    if enrichment.get("passer_par_virustotal") == 1:
                        logger.debug(f"  [SKIP] {ioc_value[:50]} already flagged.")
                        continue

                    vt_data = self.get_vt_info(ioc_value, ioc_type)

                    if vt_data:
                        enrichment.update({
                            "vt_malicious_count":    vt_data.get("vt_malicious_count", 0),
                            "vt_suspicious_count":   vt_data.get("vt_suspicious_count", 0),
                            "vt_harmless_count":     vt_data.get("vt_harmless_count", 0),
                            "vt_total_engines":      vt_data.get("vt_total_engines", 0),
                            "vt_reputation":         vt_data.get("vt_reputation"),
                            "vt_tags":               vt_data.get("vt_tags", []),
                            "vt_last_analysis_date": vt_data.get("vt_last_analysis_date"),
                            "vt_permalink":          vt_data.get("vt_permalink"),
                            # â”€â”€ Tracking flag â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                            "passer_par_virustotal": 1,
                        })
                        modified = True
                        total_enriched += 1
                        src = "LOCAL" if ioc_value in self.local_db and self._api_calls == 0 else "API"
                        logger.info(
                            f"  [OK] {ioc_value[:50]} enriched via {src} "
                            f"(malicious={vt_data.get('vt_malicious_count', 0)})"
                        )
                    else:
                        # No data yet (URL submitted for scan, hash not found, etc.)
                        # Still flag to avoid re-querying every run
                        enrichment["passer_par_virustotal"] = 0  # 0 = tried but no data

            if modified:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=4)
                logger.info(f"[SAVED] {filename}")

        self._save_db()
        logger.info(
            f"[VT] Done â€” {total_enriched} IOC(s) enriched, "
            f"{self._api_calls} API call(s) made."
        )


if __name__ == "__main__":
    enricher = VirusTotalEnricher(DB_PATH)
    enricher.run()
