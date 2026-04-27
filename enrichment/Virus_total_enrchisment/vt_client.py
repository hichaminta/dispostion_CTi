import requests
import os
import time
import logging
from dotenv import load_dotenv

# Load env from root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

logger = logging.getLogger("VTClient")

class VTClient:
    """
    Client for VirusTotal v3 API.
    Handles reports for files (hashes), IP addresses, domains, and URLs.
    """
    API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            logger.warning("VIRUSTOTAL_API_KEY NOT FOUND in .env file!")
        
        self.headers = {
            "x-apikey": self.api_key
        }

    def _get_report(self, endpoint):
        """Generic GET request to VirusTotal API."""
        if not self.api_key: return None
        
        url = f"{self.API_URL}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                return response.json().get("data", {})
            elif response.status_code == 404:
                logger.info(f"Indicator not found in VirusTotal: {endpoint}")
                return "NOT_FOUND"
            elif response.status_code == 429:
                logger.error("VirusTotal API Rate Limit Exceeded (429).")
                return "LIMIT_REACHED"
            else:
                logger.error(f"VirusTotal API Error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Network error calling VirusTotal: {e}")
            return None

    def get_file_report(self, file_hash):
        """Gets report for a file hash (MD5, SHA1, SHA256)."""
        return self._get_report(f"/files/{file_hash}")

    def get_ip_report(self, ip_address):
        """Gets report for an IP address."""
        return self._get_report(f"/ip_addresses/{ip_address}")

    def get_domain_report(self, domain):
        """Gets report for a domain."""
        return self._get_report(f"/domains/{domain}")

    def get_url_report(self, url):
        """Gets report for a URL (URL must be base64 encoded without padding for v3)."""
        import base64
        # VT v3 URLs require base64 encoding without '=' padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._get_report(f"/urls/{url_id}")
