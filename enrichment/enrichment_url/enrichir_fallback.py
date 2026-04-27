import os
import json
import logging
import sys
import socket
import time
import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv, find_dotenv

# Optional/Required libraries
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import whois
except ImportError:
    whois = None

try:
    import tldextract
except ImportError:
    tldextract = None

# Ensure we can import from project root for GeoManager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
try:
    from enrichment.geolocalisation.geo_manager import GeoManager
except ImportError:
    GeoManager = None

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("FallbackEnrichment")

# Base directory and paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_enrichment")
GEO_BASE_FILE = os.path.join(BASE_DIR, "enrichment", "geolocalisation", "geo_base.json")
load_dotenv(find_dotenv())

class FallbackEnricher:
    def __init__(self):
        self.geo_mgr = None
        if GeoManager and os.path.exists(GEO_BASE_FILE):
            try:
                self.geo_mgr = GeoManager(GEO_BASE_FILE)
                logger.info("GeoManager initialized correctly.")
            except Exception as e:
                logger.error(f"Failed to initialize GeoManager: {e}")
        
        self.common_brands = ["google", "microsoft", "facebook", "apple", "amazon", "paypal", "bancolombia"]
        self.suspect_keywords = ["login", "verify", "secure", "account", "update", "bank", "signin", "billing"]
        self.invalid_extensions = [
            '.dll', '.exe', '.png', '.jpg', '.jpeg', '.gif', '.msi', '.bat', 
            '.vbs', '.scr', '.js', '.hta', '.tmp', '.bin', '.dat', '.file', 
            '.arm', '.mpsl', '.mips', '.variant', '.ulise', '.elf', '.sh',
            '.zip', '.tar', '.rar', '.7z', '.jar', '.iso', '.lnk', '.gz'
        ]

    def is_valid_enrichment_target(self, value):
        if not value or not isinstance(value, str): return False
        val_low = value.lower()
        if any(val_low.endswith(ext) for ext in self.invalid_extensions):
            return False
        if '.' not in value:
            return False
        return True

    def dns_lookup(self, value):
        """Resolves IP for a domain."""
        logger.info(f"  [DNS] Resolving {value}...")
        try:
            hostname = value
            if "://" in value:
                hostname = urlparse(value).hostname
            if not hostname: return None
            
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception as e:
            logger.warning(f"DNS Resolution failed for {value}: {e}")
            return None

    def geo_lookup(self, ip):
        """Gets country code for an IP using GeoManager."""
        if not self.geo_mgr or not ip:
            return None
        return self.geo_mgr.get_country(ip)

    def web_lookup(self, value):
        """Fetches basic web info: effective URL, page title, and server."""
        logger.info(f"  [WEB] Scraping {value}...")
        url = value if "://" in value else f"http://{value}"
        results = {
            "effective_url": None,
            "page_title": None,
            "server": None
        }
        try:
            response = requests.get(url, timeout=8, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            results["effective_url"] = response.url
            results["server"] = response.headers.get("Server")
            
            if BeautifulSoup and response.content:
                soup = BeautifulSoup(response.content, "html.parser")
                if soup.title and soup.title.string:
                    results["page_title"] = soup.title.string.strip()
            elif response.content:
                # RegEx fallback for title
                title_match = re.search(b"<title>(.*?)</title>", response.content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    results["page_title"] = title_match.group(1).decode("utf-8", errors="ignore").strip()
            
            return results
        except Exception as e:
            logger.warning(f"Web scraping failed for {url}: {e}")
            return results

    def whois_lookup(self, value):
        """Fetches WHOIS data for a domain."""
        if not whois:
            return {}
        
        logger.info(f"  [WHOIS] Looking up {value}...")
        try:
            hostname = value
            if "://" in value:
                hostname = urlparse(value).hostname
            if not hostname: return {}

            w = whois.whois(hostname)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_days = None
            if creation_date:
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                creation_date = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)

            return {
                "creation_date": creation_date,
                "registrar": w.registrar,
                "domain_age_days": age_days
            }
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {value}: {e}")
            return {}

    def heuristic_analysis(self, value):
        """Performs simple heuristic analysis."""
        logger.info(f"  [HEURISTIC] Analyzing {value}...")
        
        matches = [kw for kw in self.suspect_keywords if kw in value.lower()]
        
        # Typosquatting detection
        is_typosquat = False
        domain_part = value
        if tldextract:
            extracted = tldextract.extract(value)
            domain_part = extracted.domain
        
        for brand in self.common_brands:
            if brand in domain_part.lower() and brand != domain_part.lower():
                is_typosquat = True
                break

        risk_level = "low"
        if is_typosquat:
            risk_level = "high"
        elif len(matches) > 0:
            risk_level = "medium"
        
        return {
            "suspicious_keywords": matches,
            "typosquat_flag": is_typosquat,
            "risk_flag": risk_level
        }

    def enrich_url_domain_fallback(self, ioc):
        """
        Main Stage 4 enrichment logic.
        Adds: _ip, country, server, page_title, effective_url, WHOIS, and Heuristics.
        """
        ioc_type = ioc.get("type")
        value = ioc.get("value")
        
        # Handle "domaine" vs "domain"
        clean_type = "domain" if ioc_type in ["domain", "domaine"] else ioc_type
        if clean_type not in ["domain", "url"]:
            return ioc

        if "ioc_enrichment" not in ioc:
            ioc["ioc_enrichment"] = {}
        
        enr = ioc["ioc_enrichment"]

        # 1. DNS & Geo
        resolved_ip = self.dns_lookup(value)
        if resolved_ip:
            if "country" not in enr or not enr["country"]:
                country = self.geo_lookup(resolved_ip)
                if country:
                    enr["country"] = country

        # 2. Web Info
        web_info = self.web_lookup(value)
        if web_info["server"] and "server" not in enr:
            enr["server"] = web_info["server"]
        if web_info["page_title"] and "page_title" not in enr:
            enr["page_title"] = web_info["page_title"]
        if web_info["effective_url"] and "effective_url" not in enr:
            enr["effective_url"] = web_info["effective_url"]

        # 3. WHOIS
        whois_data = self.whois_lookup(value)
        for k, v in whois_data.items():
            if v and k not in enr:
                enr[k] = v

        # 4. Heuristics
        heuristics = self.heuristic_analysis(value)
        enr["suspicious_keywords"] = heuristics["suspicious_keywords"]
        enr["typosquat_flag"] = heuristics["typosquat_flag"]
        enr["risk_flag"] = heuristics["risk_flag"]

        # Final Marker
        now_iso = datetime.now().isoformat()
        enr["tlp"] = "TLP:CLEAR"
        enr["enriched_at"] = now_iso
        enr["passer_par_fallback"] = 1
        
        return ioc

def run_fallback_enrichment(source_filter=None):
    """Processes files in output_enrichment and applies fallback logic."""
    if not os.path.exists(OUTPUT_DIR):
        logger.error(f"Output directory not found: {OUTPUT_DIR}")
        return

    enricher = FallbackEnricher()
    all_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith("_enriched.json")]
    
    if source_filter:
        files = [f for f in all_files if source_filter.lower() in f.lower()]
    else:
        files = all_files

    logger.info(f"### STAGE 4: FALLBACK ENRICHMENT STARTED ({len(files)} files) ###")
    
    for filename in files:
        if "otx_alienvault" in filename.lower():
            logger.info(f"--- [IGNORE] Skipping OTX source file: {filename} ---")
            continue
            
        file_path = os.path.join(OUTPUT_DIR, filename)
        logger.info(f"Processing source: {filename}")
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            modified = False
            for record in data:
                record_modified = False
                for ioc in record.get("iocs", []):
                    ioc_type = ioc.get("type")
                    ioc_value = ioc.get("value")
                    
                    # Target only URL/Domain/Domaine
                    if ioc_type not in ["domain", "url", "domaine"]:
                        continue
                    
                    enr = ioc.get("ioc_enrichment", {})
                    urlscan_score = record.get("attributes", {}).get("urlscan_score")
                    
                    # 1. Skip if already processed by Stage 4 (Don't repeat)
                    if enr.get("passer_par_fallback") == 1:
                        continue
                    
                    has_urlscan = enr.get("passer_par_urlscan") == 1
                    
                    # Target only those already scanned by URLScan (Requirement)
                    if not has_urlscan:
                        continue
                    
                    # 2. Check trigger condition:
                    # - ONLY if URLScan score is NOT 100 (incomplete/less critical data)
                    
                    should_fallback = False
                    if urlscan_score is not None:
                        try:
                            if int(urlscan_score) < 100:
                                should_fallback = True
                        except (ValueError, TypeError):
                            should_fallback = True
                    else:
                        # Scanned but no score? Treat as candidate for additional info.
                        should_fallback = True
                        
                    if should_fallback:
                        if not enricher.is_valid_enrichment_target(ioc_value):
                            continue
                            
                        logger.info(f"  [FALLBACK] Triggered for {ioc_value[:40]}...")
                        enricher.enrich_url_domain_fallback(ioc)
                        record_modified = True
                        modified = True
                
                # Update attributes if needed
                if record_modified:
                    if "attributes" not in record: record["attributes"] = {}
                    record["attributes"]["fallback_enriched"] = True

            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                logger.info(f"  [SAVED] {filename} updated with fallback data.")
            else:
                logger.info(f"  [SKIP] No candidates found in {filename}.")
                
        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Stage 4: Fallback Enrichment Module")
    parser.add_argument("-s", "--source", help="Only process a specific source")
    args = parser.parse_args()
    run_fallback_enrichment(source_filter=args.source)
