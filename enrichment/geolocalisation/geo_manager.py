import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import logging
import struct
import tempfile
import ipaddress

class GeoManager:
    def __init__(self, db_path=None):
        if db_path is None:
            # We move to .json as requested
            db_path = os.path.join(os.path.dirname(__file__), "geo_base.json")
        self.db_path = db_path
        self.logger = logging.getLogger("GeoManager")
        logging.basicConfig(encoding="utf-8", level=logging.INFO)
        self.data = self._load_db()

    def _load_db(self):
        if os.path.exists(self.db_path):
            try:
                # Check file size first - if it's too small and we expected more, log it
                size = os.path.getsize(self.db_path)
                if size == 0:
                    self.logger.warning(f"Database file {self.db_path} is empty.")
                    return {}

                with open(self.db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except json.JSONDecodeError as je:
                self.logger.error(f"JSON Decode Error in {self.db_path}: {je}")
                # Create a backup of the corrupted file for investigation
                backup_path = self.db_path + ".corrupted"
                try:
                    import shutil
                    shutil.copy2(self.db_path, backup_path)
                    self.logger.info(f"Corrupted database backed up to {backup_path}")
                except:
                    pass
                return {}
            except Exception as e:
                self.logger.error(f"Failed to load JSON database: {e}")
                return {}
        return {}

    def _save_db(self):
        """
        Saves the database to the JSON file atomically.
        Uses a temporary file and renames it to avoid corruption during crashes.
        """
        temp_path = None
        try:
            # Create a temporary file in the same directory
            fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(self.db_path), prefix=".geo_base_", suffix=".tmp")
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4)
            
            # Atomic swap
            os.replace(temp_path, self.db_path)
        except Exception as e:
            self.logger.error(f"Failed to save JSON database: {e}")
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass

    def _normalize_ip(self, ip):
        """Returns an ipaddress object or None."""
        if not ip or not isinstance(ip, str):
            return None
        try:
            # Handle CIDR or single IP
            if '/' in ip:
                network = ipaddress.ip_network(ip, strict=False)
                return network.network_address
            return ipaddress.ip_address(ip)
        except:
            return None

    def get_country(self, ip):
        """
        Looks up the country code for an IP (v4 or v6).
        """
        # 1. Normalize input
        ip_obj = self._normalize_ip(ip)
        if ip_obj is None:
            return None
        
        ip_str = str(ip_obj)
        
        # 2. Check direct IP cache
        ips_data = self.data.get("ips", {})
        entry = ips_data.get(ip_str)
        if entry:
            return entry.get("country_code")
            
        # 3. Check ranges
        ranges = self.data.get("ranges", [])
        if not ranges:
            return None
            
        # Performance Optimization: convert string ranges to ip objects once
        if not hasattr(self, "_ranges_objs"):
            self._ranges_objs = []
            for r in ranges:
                if len(r) < 3: continue
                try:
                    start_obj = ipaddress.ip_address(r[0])
                    end_obj = ipaddress.ip_address(r[1])
                    self._ranges_objs.append((start_obj, end_obj, r[2]))
                except:
                    continue
            self._ranges_objs.sort(key=lambda x: x[0])
            
        # Binary search
        low = 0
        high = len(self._ranges_objs) - 1
        while low <= high:
            mid = (low + high) // 2
            start, end, code = self._ranges_objs[mid]
            
            # Check version match before comparing
            if ip_obj.version == start.version:
                if start <= ip_obj <= end:
                    return code if code != "-" else None
                elif ip_obj < start:
                    high = mid - 1
                else:
                    low = mid + 1
            else:
                # If versions don't match, we need to adjust search
                # Usually IPv4 < IPv6 in sorted lists
                if ip_obj.version < start.version:
                    high = mid - 1
                else:
                    low = mid + 1
        
        return None

    def insert_mapping(self, ip, country_code, country_name=None, source="local_sync", auto_save=True):
        from datetime import datetime
        # Ensure new structure exists
        if "ips" not in self.data:
            if isinstance(self.data, dict) and "ranges" not in self.data:
                self.data = {"ips": self.data, "ranges": []}
            else:
                self.data["ips"] = self.data.get("ips", {})
                self.data["ranges"] = self.data.get("ranges", [])

        self.data["ips"][ip] = {
            "country_code": country_code,
            "country_name": country_name,
            "source": source,
            "updated_at": datetime.now().isoformat()
        }
        if auto_save:
            self._save_db()

    def save_cache(self):
        """Manually trigger a save of the database."""
        self._save_db()

    def sync_from_existing_data(self, enrichment_dir):
        """
        Scans all enriched JSON files to populate the local cache with already known countries.
        """
        if not os.path.exists(enrichment_dir):
            return
            
        count = 0
        for filename in os.listdir(enrichment_dir):
            if filename.endswith("_enriched.json"):
                path = os.path.join(enrichment_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        file_data = json.load(f)
                    
                    for record in file_data:
                        # Check global attributes
                        attrs = record.get("attributes", {})
                        country = attrs.get("country") or attrs.get("country_code")
                        
                        # Check each IOC
                        for ioc in record.get("iocs", []):
                            if ioc.get("type") == "ip":
                                ip = ioc.get("value")
                                # If the record has a country, map it to the IP
                                if country and len(str(country)) <= 3: # Likely a code
                                    self.insert_mapping(ip, str(country).upper(), source=f"sync:{filename}")
                                    count += 1
                                # Also check if the IOC itself has enrichment from a source
                                ioc_enr = ioc.get("ioc_enrichment", {})
                                ioc_country = ioc_enr.get("country") or ioc_enr.get("country_code")
                                if ioc_country:
                                    self.insert_mapping(ip, str(ioc_country).upper(), source=f"sync:{filename}")
                                    count += 1
                except Exception as e:
                    self.logger.error(f"Failed to sync from {filename}: {e}")
        
        self.logger.info(f"Sync complete. Added/Updated {count} IP mappings in JSON base.")

if __name__ == "__main__":
    # Self-test / sync
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    enr_dir = os.path.join(base_dir, "output_enrichment")
    gm = GeoManager()
    gm.sync_from_existing_data(enr_dir)
