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
            'ip_port': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}\b',
            'ip_range': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[1-2]?[0-9]|3[0-2])\b',
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
            "MalwareBazaar Community API": ["collect_id", "sha256_hash", "id"],
            "MalwareBazaar": ["sha256_hash", "id"], # Backward compatibility
            "ThreatFox": ["id"],
            "URLhaus": ["id"],
            "Pulsedive": ["id"],
            "FeodoTracker": ["id"],
            "CINS Army": ["ip", "id"],
            "OpenPhish": ["url", "id"],
            "VirusTotal": ["id"]
        }

        # Whitelist of benign domains to filter out false positives
        self.WHITELIST_DOMAINS = {
            "google.com", "google.org", "google.net", "google.io", "google.ai",
            "microsoft.com", "microsoft.org", "microsoft.net", "microsoft.io",
            "amazon.com", "amazon.net", "amazon.org",
            "cloudflare.com", "cloudflare.net", "cloudflare.io",
            "github.com", "github.io", "github.dev",
            "openai.com", "openai.org",
            "apple.com", "apple.net",
            "facebook.com", "facebook.net", "facebook.org",
            "sinkhole.ch", "abuse.ch", "shadowserver.org",
            "localhost", "example.com", "127.0.0.1"
        }

    def is_whitelisted(self, domain):
        """Checks if a domain or its parent is in the whitelist."""
        if not domain: return False
        domain = domain.lower().strip()
        
        # Check direct match
        if domain in self.WHITELIST_DOMAINS:
            return True
            
        # Check parent domains (e.g., api.google.com -> google.com)
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i+1:])
            if parent in self.WHITELIST_DOMAINS:
                return True
                
        return False

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

        # 1. CVE extraction
        cve_matches = re.findall(self.patterns['cve'], text, re.IGNORECASE)
        for val in set(cve_matches):
            results['cves'].append({'id': self.normalize_cve(val)})

        # 2. URL extraction (High priority to avoid collision)
        url_matches = re.findall(self.patterns['url'], text)
        for val in set(url_matches):
            val_norm = self.normalize_url(val)
            # Extraire le domaine de l'URL pour vérification whitelist
            try:
                from urllib.parse import urlparse
                domain = urlparse(val_norm).netloc.split(':')[0]
                if self.is_whitelisted(domain): continue
            except: pass
            
            results['iocs'].append({'type': 'url', 'value': val_norm})

        # 3. Email extraction (Categorized as 'autr' as requested)
        email_matches = re.findall(self.patterns['email'], text)
        for val in set(email_matches):
            results['iocs'].append({'type': 'autr', 'value': self.normalize_email(val)})

        # 4. Hash extraction (MD5, SHA1, SHA256) -> 'hashe' type
        for hash_type in ['sha256', 'sha1', 'md5']:
            matches = re.findall(self.patterns[hash_type], text)
            for val in set(matches):
                results['iocs'].append({'type': 'hashe', 'value': self.normalize_hash(val)})

        # 5. IP extraction (Range, Port, Standard) -> 'ip' type
        # Check ranges first
        ip_range_matches = re.findall(self.patterns['ip_range'], text)
        for val in set(ip_range_matches):
            results['iocs'].append({'type': 'ip', 'value': val.strip()})
            
        # Check IP with ports
        ip_port_matches = re.findall(self.patterns['ip_port'], text)
        for val in set(ip_port_matches):
            results['iocs'].append({'type': 'ip', 'value': val.strip()})

        # Check standard IPs
        ip_matches = re.findall(self.patterns['ip'], text)
        for val in set(ip_matches):
            norm_ip = self.normalize_ip(val)
            if norm_ip:
                if self.is_whitelisted(norm_ip): continue
                # Avoid adding if already part of an IP:Port or IP/Range
                is_duplicate = False
                for existing in results['iocs']:
                    if existing['type'] == 'ip' and norm_ip in existing['value']:
                        is_duplicate = True
                        break
                if not is_duplicate:
                    results['iocs'].append({'type': 'ip', 'value': norm_ip})

        # 6. Domain extraction -> 'domaine' type
        domain_matches = re.findall(self.patterns['domain'], text, re.IGNORECASE)
        for val in set(domain_matches):
            val_lower = val.lower()
            # Simple check: is it an IP?
            if self.normalize_ip(val): continue
            
            # Whitelist check
            if self.is_whitelisted(val_lower): continue
            
            # Is it part of a URL or Email or IP already found?
            is_part_of_other = False
            for ioc in results['iocs']:
                if val_lower in ioc['value'].lower():
                    is_part_of_other = True
                    break
            
            if not is_part_of_other:
                results['iocs'].append({'type': 'domaine', 'value': self.normalize_domain(val)})

        # Deduplication
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

    def _extract_attributes(self, item):
        """
        Extracts extended metadata attributes from raw JSON items.
        Standardizes field names across different sources.
        """
        attrs = {}
        
        # --- Network Info ---
        port = item.get('port') or item.get('destination_port') or item.get('dst_port')
        if port: attrs['port'] = port
        
        country = item.get('country') or item.get('countries') or item.get('countryCode') or item.get('country_code')
        if country: attrs['country'] = country
        
        asn = item.get('as_number') or item.get('asn') or item.get('asn_number')
        if asn: attrs['asn'] = asn
        
        as_owner = item.get('as_name') or item.get('as_owner') or item.get('as_orgname')
        if as_owner: attrs['as_owner'] = as_owner
        
        hostname = item.get('hostname') or item.get('host') or item.get('domain_name')
        if hostname: attrs['hostname'] = hostname

        # --- Threat Intelligence / Scoring ---
        confidence = item.get('confidence_level') or item.get('confidence') or item.get('abuseConfidenceScore')
        if confidence is not None: attrs['confidence'] = confidence
        
        reputation = item.get('reputation') or item.get('reputation_score') or item.get('score')
        if reputation is not None: attrs['reputation'] = reputation
        
        threat_type = item.get('threat_type') or item.get('threat_category') or item.get('ioc_type_desc')
        if threat_type: attrs['threat_type'] = threat_type
        
        malware = item.get('malware_printable') or item.get('malware') or item.get('malware_family')
        if malware: attrs['malware_family'] = malware

        # --- Operational Status ---
        status = item.get('status') or item.get('malware_status')
        if status: attrs['status'] = status
        
        is_compromised = item.get('is_compromised')
        if is_compromised is not None: attrs['is_compromised'] = is_compromised

        # --- Technical Hashes & Fuzzy Hashes ---
        for h_field in ['sha1_hash', 'sha1', 'sha3_384_hash', 'sha3_384', 'imphash', 'tlsh', 'ssdeep']:
            val = item.get(h_field)
            if val: attrs[h_field.replace('_hash', '')] = val

        # --- Intelligence & Sandbox ---
        intel = item.get('intelligence')
        if isinstance(intel, dict):
            for i_key, i_val in intel.items():
                if i_val: attrs[f'intel_{i_key}'] = i_val

        # --- MalwareBazaar Specifics ---
        if item.get('collect_id'): attrs['collect_id'] = item.get('collect_id')
        if item.get('reporter'): attrs['reporter'] = item.get('reporter')
        if item.get('delivery_method'): attrs['delivery_method'] = item.get('delivery_method')
        if item.get('file_size'): attrs['file_size'] = item.get('file_size')

        # --- Handle Nested Attributes (e.g. VirusTotal) ---
        if 'attributes' in item and isinstance(item['attributes'], dict):
            vt_attrs = item['attributes']
            if not attrs.get('reputation'): attrs['reputation'] = vt_attrs.get('reputation')
            if not attrs.get('status'): attrs['status'] = vt_attrs.get('status')
            if vt_attrs.get('type_description'): attrs['type_description'] = vt_attrs.get('type_description')
            if vt_attrs.get('names'): attrs['filenames'] = vt_attrs.get('names')

        return attrs

    def process_item(self, source_name, item):
        # Convert item to a string representation for global extraction
        raw_text = json.dumps(item, ensure_ascii=False)
        extracted = self.extract_from_text(raw_text)
        
        record_id = self.get_record_id(source_name, item)
        tags = self.extract_tags(item)
        refs = self.extract_references(item)
        
        # 1. Extract technical attributes (score, country, asn, etc.)
        attributes = self._extract_attributes(item)
        
        # 2. IOC-Centric Propagation: Anchor attributes to each IOC
        for ioc in extracted['iocs']:
            ioc['source'] = source_name
            if 'ioc_enrichment' not in ioc:
                ioc['ioc_enrichment'] = {}
            
            # Copy all technical attributes into the IOC enrichment block
            for k, v in attributes.items():
                if v is not None:
                    ioc['ioc_enrichment'][k] = v
        
        # Add source info to each CVE
        for cve in extracted['cves']:
            cve['source'] = source_name
            if 'ioc_enrichment' not in cve:
                cve['ioc_enrichment'] = {}
            # CVEs also benefit from knowing the source's confidence/reputation
            for k in ['confidence', 'reputation', 'status']:
                if k in attributes:
                    cve['ioc_enrichment'][k] = attributes[k]
        
        return {
            "source": source_name,
            "record_id": record_id,
            "raw_text": raw_text,
            "summary": f"Extracted {len(extracted['iocs'])} IOCs from {source_name}. Contextual attributes anchored to each indicator.",
            "iocs": extracted['iocs'],
            "cves": extracted['cves'],
            "tags": tags,
            "references": refs,
            "attributes": attributes, # Kept for record-level context
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
                
                # Update Attributes (New)
                existing_attrs = existing.get("attributes", {})
                for k, v in new_item.get("attributes", {}).items():
                    existing_attrs[k] = v
                existing["attributes"] = existing_attrs
                
                # Update collected_at if newer or missing
                new_ts = new_item.get("collected_at")
                old_ts = existing.get("collected_at")
                if new_ts and (not old_ts or new_ts > old_ts):
                    existing["collected_at"] = new_ts
                    
                # Update raw_text if missing
                if not existing.get("raw_text"):
                    existing["raw_text"] = new_item.get("raw_text")
                
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
