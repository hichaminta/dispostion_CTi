import requests
import os
import time
import logging
from dotenv import load_dotenv

# Load env from root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

logger = logging.getLogger("URLScanClient")

class URLScanClient:
    """
    Client for URLScan.io API.
    Handles submission of scans and retrieval of results.
    """
    SCAN_URL = "https://urlscan.io/api/v1/scan/"
    RESULT_URL = "https://urlscan.io/api/v1/result/"

    def __init__(self):
        self.api_key = os.getenv("URLScan_API_KEY")
        if not self.api_key:
            logger.warning("URLScan_API_KEY NOT FOUND in .env file!")
        
        self.headers = {
            "Content-Type": "application/json",
            "API-Key": self.api_key
        }

    def submit_scan(self, url, visibility="public"):
        """
        Submits a URL to urlscan.io for scanning.
        Returns the UUID if successful, None otherwise.
        """
        if not self.api_key: return None
        
        # Inter-request delay to prevent burst limits
        time.sleep(2)
        
        payload = {
            "url": url,
            "visibility": visibility
        }
        
        try:
            response = requests.post(self.SCAN_URL, headers=self.headers, json=payload, timeout=15)
            
            if response.status_code in [200, 201]:
                data = response.json()
                return data.get("uuid")
            elif response.status_code == 429:
                logger.error("URLScan API Rate Limit Exceeded (429). Returning LIMIT_REACHED.")
                return "LIMIT_REACHED"
            else:
                resp_text = response.text
                resp_json = {}
                try: resp_json = response.json()
                except: pass
                
                msg = str(resp_json.get("message", "")).lower()
                if "quota" in msg or "limit" in msg or "daily" in msg or response.status_code == 401:
                    logger.error(f"URLScan API Quota Reached: {msg}")
                    return "LIMIT_REACHED"
                
                if "DNS Error" in resp_text or "could not resolve" in resp_text.lower():
                    return "DNS_ERROR"
                else:
                    logger.error(f"Failed to submit scan for {url}: {response.status_code} - {resp_text}")
                return None
        except Exception as e:
            logger.error(f"Error submitting to URLScan: {e}")
            return None

    def fetch_result(self, uuid):
        """
        Attempts to fetch the results for a given UUID.
        Returns the JSON result if ready, 'PENDING' if still scanning, or None if error.
        """
        if not self.api_key or not uuid: return None
        
        # Small delay before fetch to avoid hitting limits
        time.sleep(0.5)
        
        try:
            response = requests.get(f"{self.RESULT_URL}{uuid}/", headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # Scan still in progress
                return "PENDING"
            elif response.status_code == 429:
                logger.warning("URLScan API Rate Limit hit during fetch. Returning PENDING.")
                return "PENDING"
            else:
                logger.error(f"Error fetching URLScan result for {uuid}: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error fetching from URLScan: {e}")
            return None
