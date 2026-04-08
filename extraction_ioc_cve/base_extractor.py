import re
import json
import ipaddress
import os
from datetime import datetime

class BaseExtractor:
    def __init__(self):
        # Regex patterns
        self.patterns = {
            'ip': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            'url': r'\bhttps?://[^\s<>"]+\b',
            'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'cve': r'CVE-\d{4}-\d{4,}'
        }

        # Mapping of sources to their primary ID fields for deduplication
        self.SOURCE_ID_FIELDS = {
            "OTX AlienVault": ["id", "pulse_id"],
            "PhishTank": ["phish_id", "id"],
            "NVd": ["id", "cve_id"],
            "AbuseIPDB": ["ipAddress", "id"],
            "MalwareBazaar": ["sha256_hash", "id"],
            "ThreatFox": ["id"],
            "URLhaus": ["id"],
            "Pulsedive": ["id"],
            "FeodoTracker": ["id"],
            "CINS Army": ["ip", "id"],
            "OpenPhish": ["url", "id"],
            "VirusTotal": ["id"]
        }
        
    def normalize_ip(self, val):
        try:
            return str(ipaddress.ip_address(val.strip()))
        except ValueError:
            return None

    def normalize_domain(self, val):
        return val.strip().lower()

    def normalize_url(self, val):
        return val.strip()

    def normalize_email(self, val):
        return val.strip().lower()

    def normalize_hash(self, val):
        return val.strip().lower()

    def normalize_cve(self, val):
        return val.strip().upper()

    def extract_from_text(self, text):
        results = {
            'iocs': [],
            'cves': []
        }
        
        if not text:
            return results

        # CVE extraction
        cve_matches = re.findall(self.patterns['cve'], text, re.IGNORECASE)
        for val in set(cve_matches):
            results['cves'].append({'id': self.normalize_cve(val)})

        # IOC extraction
        # We search for hashes first (longest first) to avoid overlaps if any
        for hash_type in ['sha256', 'sha1', 'md5']:
            matches = re.findall(self.patterns[hash_type], text)
            for val in set(matches):
                results['iocs'].append({'type': hash_type, 'value': self.normalize_hash(val)})
                # Remove found hashes from text to avoid triple-matching with other regex if they overlap (unlikely but safe)
                # Actually, no need for that as hashes are fixed length and don't match IPs/URLs/etc.

        # Emails
        email_matches = re.findall(self.patterns['email'], text)
        for val in set(email_matches):
            results['iocs'].append({'type': 'email', 'value': self.normalize_email(val)})

        # URLs
        url_matches = re.findall(self.patterns['url'], text)
        for val in set(url_matches):
            results['iocs'].append({'type': 'url', 'value': self.normalize_url(val)})

        # IPs
        ip_matches = re.findall(self.patterns['ip'], text)
        for val in set(ip_matches):
            norm_ip = self.normalize_ip(val)
            if norm_ip:
                results['iocs'].append({'type': 'ip', 'value': norm_ip})

        # Domains (only if not already part of a URL/Email/IP)
        # We'll filter domains that are substrings of URLs or Emails we already found
        domain_matches = re.findall(self.patterns['domain'], text, re.IGNORECASE)
        for val in set(domain_matches):
            val_lower = val.lower()
            # Simple check: is it an IP?
            if self.normalize_ip(val):
                continue
            
            # Is it part of a URL or Email?
            is_part_of_other = False
            for ioc in results['iocs']:
                if ioc['type'] in ['url', 'email'] and val_lower in ioc['value'].lower():
                    is_part_of_other = True
                    break
            
            if not is_part_of_other:
                results['iocs'].append({'type': 'domain', 'value': self.normalize_domain(val)})

        # Remove duplicates from the list of dicts
        unique_iocs = []
        seen_iocs = set()
        for ioc in results['iocs']:
            key = (ioc['type'], ioc['value'])
            if key not in seen_iocs:
                seen_iocs.add(key)
                unique_iocs.append(ioc)
        results['iocs'] = unique_iocs

        unique_cves = []
        seen_cves = set()
        for cve in results['cves']:
            if cve['id'] not in seen_cves:
                seen_cves.add(cve['id'])
                unique_cves.append(cve)
        results['cves'] = unique_cves

        return results

    def extract_tags(self, item):
        """
        Extracts tags/labels from various common fields in raw JSON data.
        """
        tags = set()
        tag_fields = ['tags', 'tag', 'threat_type', 'threat_name', 'labels', 'category', 'status']
        
        for field in tag_fields:
            val = item.get(field)
            if isinstance(val, list):
                for t in val:
                    if isinstance(t, str): tags.add(t.strip().lower())
            elif isinstance(val, str):
                tags.add(val.strip().lower())
        
        # Also look for things like 'malware_name' (specific to MalwareBazaar/ThreatFox)
        if item.get('malware_printable'): tags.add(item.get('malware_printable').strip().lower())
        if item.get('malware'): tags.add(item.get('malware').strip().lower())
        
        return sorted(list(tags))

    def extract_references(self, item):
        """
        Extracts external links/references.
        """
        refs = set()
        ref_fields = ['references', 'reference', 'url', 'source_url', 'link']
        
        for field in ref_fields:
            val = item.get(field)
            if isinstance(val, list):
                for r in val:
                    if isinstance(r, str) and (r.startswith('http') or r.startswith('www')):
                        refs.add(r.strip())
            elif isinstance(val, str) and (val.startswith('http') or val.startswith('www')):
                refs.add(val.strip())
        
        return sorted(list(refs))

    def get_record_id(self, source_name, item):
        id_fields = self.SOURCE_ID_FIELDS.get(source_name, ["id"])
        for field in id_fields:
            if field in item and item[field]:
                return str(item[field])
        
        # Fallback to indicator value if it makes sense for "fusion"
        if "ioc" in item: return str(item["ioc"])
        if "url" in item: return str(item["url"])
        if "ip" in item: return str(item["ip"])
        if "sha256" in item: return str(item["sha256"])
        
        # Absolute fallback: hash of the raw content
        return str(hash(json.dumps(item, sort_keys=True)))

    def process_item(self, source_name, item):
        # Convert item to a string representation for global extraction
        raw_text = json.dumps(item, ensure_ascii=False)
        extracted = self.extract_from_text(raw_text)
        
        record_id = self.get_record_id(source_name, item)
        tags = self.extract_tags(item)
        refs = self.extract_references(item)
        
        # Add source info to each IOC/CVE for traceability
        for ioc in extracted['iocs']:
            ioc['source'] = source_name
        for cve in extracted['cves']:
            cve['source'] = source_name
        
        return {
            "source": source_name,
            "record_id": record_id,
            "raw_text": raw_text,
            "summary": f"Extracted {len(extracted['iocs'])} IOCs and {len(extracted['cves'])} CVEs from {source_name}",
            "iocs": extracted['iocs'],
            "cves": extracted['cves'],
            "tags": tags,
            "references": refs,
            "collected_at": item.get('collected_at') or item.get('extracted_at') or item.get('lastReportedAt') or item.get('last_modified') or item.get('published')
        }

    def merge_results(self, existing_list, new_list, source_name):
        """
        Merges new_list into existing_list based on record_id.
        Handles deduplication and 'fusion' of entries.
        """
        indexed_data = {}
        no_id_list = []
        
        # Build index from existing records, migrating missing record_ids
        for item in existing_list:
            rid = item.get("record_id")
            if not rid:
                # Try to migrate: parse raw_text to extract ID
                try:
                    raw = json.loads(item.get("raw_text", "{}"))
                    rid = self.get_record_id(source_name, raw)
                    item["record_id"] = rid
                except:
                    pass
            
            if rid:
                # If multiple old records share the same ID, they'll be merged later or the last one wins
                indexed_data[rid] = item
            else:
                no_id_list.append(item)
        
        for new_item in new_list:
            rid = new_item.get("record_id")
            if not rid:
                no_id_list.append(new_item)
                continue
                
            if rid in indexed_data:
                # Fusion logic
                existing = indexed_data[rid]
                
                # Update IOCs
                existing_iocs = existing.get("iocs", [])
                seen_iocs = {(i["type"], i["value"]) for i in existing_iocs}
                for ioc in new_item.get("iocs", []):
                    if (ioc["type"], ioc["value"]) not in seen_iocs:
                        existing_iocs.append(ioc)
                        seen_iocs.add((ioc["type"], ioc["value"]))
                existing["iocs"] = existing_iocs
                
                # Update CVEs
                existing_cves = existing.get("cves", [])
                seen_cves = {c["id"] for c in existing_cves}
                for cve in new_item.get("cves", []):
                    if cve["id"] not in seen_cves:
                        existing_cves.append(cve)
                        seen_cves.add(cve["id"])
                existing["cves"] = existing_cves
                
                # Update Tags
                existing_tags = set(existing.get("tags", []))
                for t in new_item.get("tags", []):
                    existing_tags.add(t)
                existing["tags"] = sorted(list(existing_tags))
                
                # Update References
                existing_refs = set(existing.get("references", []))
                for r in new_item.get("references", []):
                    existing_refs.add(r)
                existing["references"] = sorted(list(existing_refs))
                
                # Update summary
                existing["summary"] = f"Merged data from {source_name}. Total {len(existing_iocs)} IOCs, {len(existing_cves)} CVEs, and {len(existing['tags'])} tags."
                
                # Update timestamp if newer
                new_ts = new_item.get("collected_at")
                old_ts = existing.get("collected_at")
                if new_ts and (not old_ts or new_ts > old_ts):
                    existing["collected_at"] = new_ts
                    # Update raw_text to the most recent version
                    existing["raw_text"] = new_item.get("raw_text", existing.get("raw_text"))
            else:
                indexed_data[rid] = new_item
        
        return list(indexed_data.values()) + no_id_list

    def filter_by_timestamp(self, data, oldest_time_str, recent_time_str):
        if not oldest_time_str and not recent_time_str:
            return data
            
        oldest_time = None
        recent_time = None
        
        try:
            if oldest_time_str:
                clean_oldest = oldest_time_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
                oldest_time = datetime.fromisoformat(clean_oldest)
            if recent_time_str:
                clean_recent = recent_time_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
                recent_time = datetime.fromisoformat(clean_recent)
        except:
            # If we can't parse tracking dates, we return all data to be safe
            return data

        filtered = []
        for item in data:
            # Try various common timestamp fields
            ts_str = item.get('collected_at') or item.get('extracted_at') or item.get('lastReportedAt') or item.get('last_modified') or item.get('published')
            if not ts_str:
                filtered.append(item)
                continue
            
            try:
                # Handle common formats
                clean_ts = ts_str.replace('Z', '+00:00').replace(' UTC', '+00:00')
                item_time = datetime.fromisoformat(clean_ts)
                
                is_outside_range = False
                if oldest_time and item_time < oldest_time:
                    is_outside_range = True
                if recent_time and item_time > recent_time:
                    is_outside_range = True
                
                if is_outside_range:
                    filtered.append(item)
            except:
                filtered.append(item) # If we can't parse, we process it to be safe
                
        return filtered
