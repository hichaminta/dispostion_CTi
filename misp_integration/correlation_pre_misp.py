import os
import json
import re
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CorrelationPreMISP")


# ──────────────────────────────────────────────
# RISK SCORER  (classe manquante — reconstruite)
# ──────────────────────────────────────────────
class RiskScorer:
    """Calcul de score IOC, score event, confiance et MITRE."""

    SOURCE_CONFIDENCE = {
        "nvd": 100, "nVd": 100,
        "spamhaus": 95, "malwarebazaar community api": 95,
        "threatfox": 90, "feodotracker": 90,
        "dfir report": 88,             # Articles rédigés par experts DFIR, IOCs validés
        "abuseipdb": 85, "urlhaus": 80,
        "otx alienvault": 75, "cins army": 75,
        "phishtank": 70, "openphish": 70, "pulsedive": 70,
    }

    MITRE_MAP = {
        "Botnet":      ["T1583.001", "T1071.001", "T1090"],
        "RAT":         ["T1059", "T1021", "T1105"],
        "Stealer":     ["T1555", "T1056", "T1041"],
        "Ransomware":  ["T1486", "T1490", "T1489"],
        "Dropper":     ["T1105", "T1204", "T1027"],
        "Phishing":    ["T1566.001", "T1598", "T1056.003"],
        "Credential":  ["T1566", "T1056", "T1114"],
        "RCE":         ["T1190", "T1059", "T1068"],
        "LPE":         ["T1068", "T1134"],
        "SQLi":        ["T1190", "T1505.003"],
        "XSS":         ["T1059.007"],
        "DoS":         ["T1498", "T1499"],
        "Cryptominer": ["T1496", "T1059"],
        "Wiper":       ["T1485", "T1490"],
    }

    @staticmethod
    def _get_level(score: float) -> str:
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        return "low"

    @staticmethod
    def calculate_ioc_score(ioc: dict, tags: list, malware_family: str = None) -> tuple:
        """
        Calcule le score de risque d'un IOC individuel (0-100).
        Basé sur : VT, abuseScore, status online, risk_flag, typosquat,
                   suspicious_keywords, tf_confidence, intel_downloads.
        """
        score = 0.0
        e = ioc.get("enrichment", {})

        vt   = float(e.get("vt_malicious_count") or 0)
        abuse = float(e.get("abuseConfidenceScore") or 0)
        tf_conf = float(e.get("confidence") or 0)

        # VT (max 30)
        if vt >= 50:   score += 30
        elif vt >= 10: score += 22
        elif vt >= 1:  score += 10

        # AbuseIPDB (max 20)
        score += min(20, abuse * 0.2)

        # ThreatFox confidence (max 10)
        score += min(10, tf_conf * 0.1)

        # Comportemental
        if e.get("status") == "online":    score += 15
        if e.get("risk_flag") == "high":   score += 10
        if e.get("typosquat_flag") is True: score += 5
        if e.get("suspicious_keywords"):   score += 5

        # MalwareBazaar intel_downloads (max 10) — peut être string
        try:
            dl = int(e.get("intel_downloads") or 0)
        except (ValueError, TypeError):
            dl = 0
        if dl >= 500:   score += 10
        elif dl >= 100: score += 5

        # Bonus malware connu
        if malware_family:
            score += 5

        # Bonus tags critiques
        critical_tags = {"emotet", "qakbot", "lockbit", "ryuk", "conti", "blackcat"}
        for t in tags:
            if t.lower() in critical_tags:
                score += 5
                break

        score = min(100.0, score)
        level = RiskScorer._get_level(score)

        if score >= 80:   action = "escalate"
        elif score >= 60: action = "investigate"
        elif score >= 40: action = "monitor"
        else:             action = "monitor_quiet"

        return round(score, 1), level, action

    @staticmethod
    def calculate_confidence_score(event: dict, source_list: list) -> float:
        """
        Confiance globale de l'event (0-100).
        Basée sur : fiabilité des sources + nombre de sources + diversité IOCs.
        """
        if not source_list:
            return 50.0

        # Moyenne pondérée des scores de sources
        conf_scores = []
        for src in source_list:
            key = src.lower().strip()
            for k, v in RiskScorer.SOURCE_CONFIDENCE.items():
                if k in key or key in k:
                    conf_scores.append(v)
                    break
            else:
                conf_scores.append(50)

        base = sum(conf_scores) / len(conf_scores)

        # Bonus multi-sources (max +15)
        multi_bonus = min(15, (len(source_list) - 1) * 5)

        # Bonus diversité IOCs (max +10)
        ioc_types = {ioc.get("type") for ioc in event.get("iocs", []) if isinstance(ioc, dict)}
        div_bonus = min(10, len(ioc_types) * 3)

        return round(min(100.0, base + multi_bonus + div_bonus), 1)

    @staticmethod
    def infer_attack_type(event_type: str, tags: list, iocs: list) -> str:
        """Infère attack_type depuis les tags et IOCs quand non défini."""
        tag_map = {
            "botnet": "Botnet", "emotet": "Botnet", "qakbot": "Botnet", "mirai": "Botnet",
            "rat": "RAT", "remcos": "RAT", "asyncrat": "RAT",
            "stealer": "Stealer", "redline": "Stealer", "lumma": "Stealer",
            "ransomware": "Ransomware", "lockbit": "Ransomware",
            "dropper": "Dropper", "loader": "Dropper",
            "phishing": "Phishing", "credential": "Credential",
            "rce": "RCE", "sqli": "SQLi", "xss": "XSS",
        }
        for t in tags:
            tl = t.lower()
            if tl in tag_map:
                return tag_map[tl]

        if event_type == "phishing":
            return "Phishing"
        if event_type == "vulnerability":
            return "Exploit"

        return "Other"

    @staticmethod
    def get_mitre_bonus(attack_type: str) -> list:
        """Retourne les techniques MITRE associées à l'attack_type."""
        return RiskScorer.MITRE_MAP.get(attack_type, [])


# ──────────────────────────────────────────────
# IOC CORRECTOR
# ──────────────────────────────────────────────
class IOCCorrector:
    IP_REGEX    = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/\d+)?$'
    MD5_REGEX   = r'^[a-fA-F0-9]{32}$'
    SHA1_REGEX  = r'^[a-fA-F0-9]{40}$'
    SHA256_REGEX= r'^[a-fA-F0-9]{64}$'
    CVE_REGEX   = r'^CVE-\d{4}-\d{4,7}$'

    @staticmethod
    def fix_type(value, current_type):
        value = str(value).strip()
        if value.lower().startswith(('http://', 'https://')):
            return "url"
        if re.match(IOCCorrector.IP_REGEX, value):
            return "ip"
        if re.match(IOCCorrector.SHA256_REGEX, value):
            return "sha256"
        if re.match(IOCCorrector.SHA1_REGEX, value):
            return "sha1"
        if re.match(IOCCorrector.MD5_REGEX, value):
            return "md5"
        if re.match(IOCCorrector.CVE_REGEX, value.upper()):
            return "cve"
        if current_type in ["domain", "domaine", "hostname"]:
            return "domain"
        # 'hashe' est un type malwarebazaar non standard → résoudre par longueur
        if current_type == "hashe":
            if re.match(IOCCorrector.SHA256_REGEX, value): return "sha256"
            if re.match(IOCCorrector.SHA1_REGEX,   value): return "sha1"
            if re.match(IOCCorrector.MD5_REGEX,    value): return "md5"
            return "hash"
        return current_type

    @staticmethod
    def normalize_url(url):
        if not url: return url
        url = url.strip().lower()
        parsed = urlparse(url)
        if parsed.path == '/':
            url = url.rstrip('/')
        return url


# ──────────────────────────────────────────────
# EVENT NAME EXTRACTOR
# ──────────────────────────────────────────────
class EventNameExtractor:

    # Sources qui ont une description narrative exploitable
    NARRATIVE_SOURCES = {
        "otx alienvault", "alienvault", "otx",
        "pulsedive",      # parfois
        "dfir report",    # articles avec titre + NLP analysis complet
    }

    # Patterns regex ordonnés par fiabilité
    CAMPAIGN_PATTERNS = [
        # dubbed 'TrueChaos' / dubbed "Operation Frost"
        (r"""dubbed\s+['"]?([A-Z][A-Za-z0-9\s\-']+?)['"]?(?:\s|,|\.|$)""", "dubbed"),
        # campaign named / operation called
        (r"""(?:campaign|operation)\s+(?:named|called|dubbed)\s+['"]?([A-Z][A-Za-z0-9\s\-]+?)['"]?(?:\s|,|\.|$)""", "campaign_named"),
        # Operation XYZ
        (r"""Operation\s+([A-Z][A-Za-z0-9\-]+)""", "operation"),
        # APT28 / TA505 / UNC2452
        (r"""\b(APT\d+|TA\d+|UNC\d+|FIN\d+|LAZARUS|SANDWORM|COZY\s*BEAR|FANCY\s*BEAR)\b""", "apt_group"),
        # "Yurei is a ransomware/malware/campaign" — nom propre avant is a
        (r"""\b([A-Z][a-z]{3,20})\s+is\s+(?:a\s+)?(?:new\s+)?(?:\w+\s+){0,2}(?:ransomware|malware|campaign|backdoor|stealer)\b""", "x_is_a"),
        (r"""\b([A-Z][a-z]{3,20})\s+(?:ransomware|malware|group|gang|actor|operation)\b""", "malware_name"),
        # supply chain attack on XYZ
        (r"""supply\s+chain\s+attack\s+(?:on|against|targeting)\s+([A-Za-z0-9\-\.]+)""", "supply_chain"),
    ]

    CVE_PATTERN     = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    PRODUCT_PATTERN = re.compile(
        r'(?:in|the)\s+([A-Z][A-Za-z0-9]+(?:\s[A-Za-z]+)?)\s+'
        r'(?:client|server|application|platform|library|framework|plugin|extension)',
        re.IGNORECASE
    )

    # Tags qui indiquent une campagne nommée
    CAMPAIGN_TAG_KEYWORDS = [
        "ransomware", "campaign", "apt", "operation", "attack",
        "zero-day", "supply chain", "backdoor", "espionage",
    ]

    # Familles malware connues pour fallback
    KNOWN_FAMILIES = {
        "emotet", "qakbot", "lockbit", "ryuk", "conti", "blackcat", "alphv",
        "remcos", "njrat", "asyncrat", "redline", "lumma", "clearfake",
        "yurei", "mozi", "mirai", "trickbot", "dridex", "havoc",
    }

    @classmethod
    def is_narrative_source(cls, source: str) -> bool:
        """Retourne True si la source a typiquement une description narrative."""
        return source.lower().strip() in cls.NARRATIVE_SOURCES

    @classmethod
    def extract(cls, record: dict) -> Optional[str]:
        """
        Point d'entrée principal.
        Retourne un nom d'event court (ex: 'CAMPAIGN-TrueChaos', 'CVE-2026-3502-TrueConf')
        ou None si aucun signal trouvé.
        """
        desc = record.get("description", "") or ""
        tags = [t.lower() for t in record.get("tags", [])]
        attrs = record.get("attributes", {})
        nlp   = attrs.get("nlp_analysis", {})

        # 1. Patterns regex sur la description
        if desc:
            name = cls._extract_from_description(desc)
            if name:
                return name

        # 2. Tags campagne spécifiques
        name = cls._extract_from_tags(tags)
        if name:
            return name

        # 3. CVE + produit ciblé
        name = cls._extract_cve_event(desc, record.get("cves", []))
        if name:
            return name

        # 4. NLP vendors/products déjà extraits dans enrichissement
        vendors = nlp.get("vendors", [])
        for v in vendors:
            vl = v.lower()
            if vl in cls.KNOWN_FAMILIES:
                return f"CAMPAIGN-{v.upper()}"

        return None

    @classmethod
    def _extract_from_description(cls, desc: str) -> Optional[str]:
        for pattern, ptype in cls.CAMPAIGN_PATTERNS:
            m = re.search(pattern, desc, re.IGNORECASE)
            if m:
                raw = m.group(1).strip().strip("'\"")
                # Filtrer les faux positifs trop génériques
                if len(raw) < 3 or raw.lower() in {"the", "a", "an", "targeted", "active"}:
                    continue
                clean = raw.replace(" ", "-").upper()

                if ptype in ("operation",):
                    return f"OPERATION-{clean}"
                if ptype == "apt_group":
                    return f"ACTOR-{clean}"
                if ptype == "supply_chain":
                    return f"SUPPLY-CHAIN-{clean.upper()}"
                return f"CAMPAIGN-{clean}"
        return None

    @classmethod
    def _extract_from_tags(cls, tags: list) -> Optional[str]:
        """Cherche un tag qui ressemble à un nom de campagne."""
        for tag in tags:
            # Exclure les tags génériques
            if any(tag.startswith(p) for p in ("reliability:", "soc_", "tlp:", "cve-")):
                continue
            # Tag contenant un mot-clé campagne
            for kw in cls.CAMPAIGN_TAG_KEYWORDS:
                if kw in tag and len(tag) > len(kw) + 2:
                    clean = tag.replace(" ", "-").replace("_", "-").upper()
                    return f"CAMPAIGN-{clean}"
        # Tag qui est directement un nom propre (majuscule dans le tag original)
        return None

    @classmethod
    def _extract_cve_event(cls, desc: str, cves: list) -> Optional[str]:
        """CVE + produit ciblé → ex: CVE-2026-3502-TRUECONF"""
        # CVE depuis description
        cve_matches = cls.CVE_PATTERN.findall(desc)
        # CVE depuis le champ cves[]
        if not cve_matches and cves:
            for c in cves:
                cid = c if isinstance(c, str) else c.get("id", "")
                if cid:
                    cve_matches.append(cid)

        if not cve_matches:
            return None

        cve_id = cve_matches[0].upper()

        # Produit ciblé depuis description
        product_m = cls.PRODUCT_PATTERN.search(desc)
        if product_m:
            product = product_m.group(1).upper().replace(" ", "-")
            return f"{cve_id}-{product}"

        return cve_id  # juste le CVE si pas de produit détecté


# ──────────────────────────────────────────────
# THREAT CORRELATOR
# ──────────────────────────────────────────────
class ThreatCorrelator:

    def __init__(self, input_dir, output_dir):
        self.input_dir  = input_dir
        self.output_dir = output_dir
        self.events = {}
        self.has_new_data = False

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        self._load_existing_events()

    def _load_existing_events(self):
        try:
            files = [f for f in os.listdir(self.output_dir) if f.startswith("correlation_file_") and f.endswith(".json")]
            if not files:
                output_file = os.path.join(self.output_dir, "correlated_events_soc_enriched.json")
            else:
                latest_file = max(files)
                output_file = os.path.join(self.output_dir, latest_file)
        except Exception:
            output_file = os.path.join(self.output_dir, "correlated_events_soc_enriched.json")

        if not os.path.exists(output_file):
            return
        try:
            with open(output_file, encoding='utf-8') as f:
                data = json.load(f)
            for event in data:
                gid = event.get("group_id")
                if not gid: continue
                event["tags"]        = set(event.get("tags", []))
                event["source_list"] = set(event.get("source_list", []))
                ioc_dict = {}
                for ioc in event.get("iocs", []):
                    ioc["sources"]   = set(ioc.get("sources", []))
                    ioc["relations"] = set(ioc.get("relations", []))
                    ioc_dict[ioc["value"]] = ioc
                event["iocs"] = ioc_dict
                self.events[gid] = event
            logger.info(f"Loaded {len(self.events)} existing events.")
        except Exception as e:
            logger.error(f"Error loading existing events: {e}")

    def extract_brand(self, attributes):
        title = str(attributes.get('urlscan_page_title', attributes.get('page_title', ''))).lower()
        brands = ['facebook','dropbox','docusign','microsoft','google','apple',
                  'netflix','amazon','paypal','outlook','linkedin','adobe',
                  'binance','metamask','ledger']
        for brand in brands:
            if brand in title:
                return brand.capitalize()
        return None

    def get_domain_from_url(self, url):
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc if parsed.netloc else None
            if netloc and ":" in netloc:
                netloc = netloc.split(":")[0]
            return netloc
        except:
            return None

    def process_files(self):
        logger.info("Phase 1 — Loading and Grouping Data...")
        all_files = [f for f in os.listdir(self.input_dir) if f.endswith('_enriched.json')]

        if not all_files:
            logger.info("No files to process.")
            return

        for filename in all_files:
            filepath = os.path.join(self.input_dir, filename)
            try:
                with open(filepath, encoding='utf-8') as f:
                    data = json.load(f)
                
                new_records = []
                needs_save = False
                for record in data:
                    if record.get('passer_par_correler') != 1:
                        new_records.append(record)
                        record['passer_par_correler'] = 1
                        needs_save = True

                if new_records:
                    self.has_new_data = True
                    self._process_records(new_records)
                    logger.info(f"[OK] {filename} : {len(new_records)} new records processed.")
                else:
                    logger.info(f"[SKIP] {filename} : No new records found.")
                    
                if needs_save:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=4)
                    
            except Exception as e:
                logger.error(f"Error loading {filename}: {e}")

    def _process_records(self, records):
        for record in records:
            source       = record.get('source', 'Unknown')
            attributes   = record.get('attributes', {})
            collected_at = record.get('collected_at', datetime.now().isoformat())
            date_str     = collected_at.split('T')[0]

            cves = record.get('cves', [])
            malware_family = (
                attributes.get('malware_family') or
                next((ioc.get('ioc_enrichment', {}).get('malware_family')
                      for ioc in record.get('iocs', [])
                      if ioc.get('ioc_enrichment', {}).get('malware_family')), None) or
                next((t for t in record.get('tags', [])
                      if t.lower() in ['clearfake','mozi','lumma','redline','stealer',
                                        'remcos','nanocore','emotet','qakbot','mirai',
                                        'gafgyt','cobaltstrike','agenttesla','avemaria']), None)
            )
            if malware_family:
                malware_family = malware_family.title()

            group_id   = None
            event_meta = {"name": "", "type": "", "threat_type": ""}

            # 0. DFIR Report — traitement prioritaire (NLP actor > malware_family > CVE > title)
            if source.lower() == "dfir report":
                nlp = attributes.get("nlp_analysis", {})
                actors = nlp.get("actor", [])

                if actors:
                    # Grouper par acteur principal détecté par NLP
                    actor_slug = re.sub(r'[^A-Z0-9]', '-', actors[0].upper())
                    group_id = f"DFIR-{actor_slug}"
                    event_meta = {
                        "name":        f"DFIR Report — {actors[0]} Campaign",
                        "type":        "malware",
                        "threat_type": "threat_report",
                    }
                elif malware_family:
                    # Famille connue mais pas d'acteur NLP explicite
                    group_id = f"DFIR-MAL-{malware_family.upper()}"
                    event_meta = {
                        "name":        f"DFIR Report — {malware_family} Incident",
                        "type":        "malware",
                        "threat_type": "threat_report",
                    }
                elif cves:
                    # Article de vulnérabilité (dfir_report_vuln_enriched)
                    cve_obj = cves[0]
                    cve_id  = cve_obj if isinstance(cve_obj, str) else cve_obj.get("id", "UNKNOWN")
                    group_id = f"DFIR-{cve_id.upper()}"
                    event_meta = {
                        "name":        f"DFIR Report — {cve_id} Exploitation",
                        "type":        "vulnerability",
                        "threat_type": "exploit",
                    }
                else:
                    # Fallback : slug du titre de l'article
                    title = record.get("description", record.get("record_id", "UNKNOWN"))
                    title_slug = re.sub(r'[^A-Z0-9]', '-', title.upper())[:40].strip('-')
                    group_id = f"DFIR-{title_slug}"
                    event_meta = {
                        "name":        f"DFIR Report — {title[:60]}",
                        "type":        "suspicious",
                        "threat_type": "threat_report",
                    }

            # 1. CVE
            elif cves:
                cve_obj = cves[0]
                cve_id  = cve_obj if isinstance(cve_obj, str) else cve_obj.get('id', 'UNKNOWN')
                group_id   = cve_id.upper() # cve_id already contains "CVE-"
                event_meta = {"name": f"Vulnerability - {cve_id}", "type": "vulnerability", "threat_type": "exploit"}

            # 2. Malware with Known Family (Priority over generic sample)
            elif malware_family and source.lower() != "dfir report":
                group_id   = f"MAL-{malware_family.upper()}"
                event_meta = {"name": f"Malware - {malware_family}", "type": "malware", "threat_type": "payload_delivery"}

            # 3. MalwareBazaar (Generic Sample fallback)
            elif source.lower() == 'malwarebazaar community api':
                sample_id = attributes.get('collect_id') or record.get('record_id')
                group_id   = sample_id.upper() # sample_id already contains "MB-"
                event_meta = {"name": f"Malware Sample - {sample_id}", "type": "malware", "threat_type": "payload_delivery"}

            # 4. Phishing
            elif source.lower() in ['openphish', 'phishtank']:
                brand  = self.extract_brand(attributes)
                domain = ""
                country = "Unknown"
                if record.get('iocs'):
                    domain = self.get_domain_from_url(record['iocs'][0].get('value')) or ""
                    # Extraction du country depuis l'enrichissement IOC (urlscan)
                    ioc_enrich = record['iocs'][0].get('ioc_enrichment', {})
                    country = ioc_enrich.get('urlscan_country') or ioc_enrich.get('country') or "Unknown"
                
                label    = brand if brand else (domain if domain else "Unknown")
                country  = str(country).upper()
                
                group_id = f"PHISH-{country}-{label}-{date_str}"
                event_meta = {"name": f"Phishing Campaign - {country} - {label} - {date_str}", "type": "phishing", "threat_type": "social_engineering"}

            # 5. Infrastructure (spamhaus, cins)
            elif source.lower() in ['abuseipdb', 'spamhaus', 'cins army']:
                country = attributes.get('country')
                if not country:
                    for ioc in record.get('iocs', []):
                        ioc_e = ioc.get('ioc_enrichment', {})
                        country = ioc_e.get('countryCode') or ioc_e.get('country') or ioc_e.get('urlscan_country')
                        if country:
                            break
                if not country:
                    country = "Unknown"
                country = str(country).upper()
                group_id = f"INFRA-{source.upper().replace(' ','_')}-{country}"
                event_meta = {"name": f"Suspicious Infrastructure - {source.title()} - {country}", "type": "suspicious", "threat_type": "infrastructure"}

            # 6. Narrative sources (AlienVault OTX...) — extraction NLP du nom d'event
            elif EventNameExtractor.is_narrative_source(source):
                extracted = EventNameExtractor.extract(record)
                if extracted:
                    group_id   = extracted
                    etype      = "vulnerability" if extracted.startswith("CVE-") else "malware" if any(k in extracted for k in ("MALWARE","CAMPAIGN","ACTOR","OPERATION")) else "suspicious"
                    event_meta = {"name": f"CTI Event - {extracted.replace('-',' ').title()}", "type": etype, "threat_type": "related"}
                    logger.info(f"  NLP extracted group_id: {extracted} (source: {source})")
                else:
                    group_id   = f"GEN-{source.upper().replace(' ','_')}-{date_str}"
                    event_meta = {"name": f"Suspicious Activity - {source}", "type": "suspicious", "threat_type": "related"}

            # 7. Fallback générique
            else:
                group_id = f"GEN-{source.upper().replace(' ','_')}-{date_str}"
                event_meta = {"name": f"Suspicious Activity - {source.title()}", "type": "suspicious", "threat_type": "related"}


            # Créer l'event si nouveau
            if group_id not in self.events:
                # Pour NVD: extraire cvss depuis cves[].ioc_enrichment
                cvss_from_cve = 0.0
                if cves:
                    try:
                        cve_obj = cves[0]
                        cvss_from_cve = float(
                            cve_obj.get('ioc_enrichment', {}).get('cvss_score', 0) or
                            attributes.get('cvss_score', 0) or 0
                        )
                    except:
                        cvss_from_cve = float(attributes.get('cvss_score', 0) or 0)

                self.events[group_id] = {
                    "group_id":         group_id,
                    "event_name":       event_meta["name"],
                    "event_type":       event_meta["type"],
                    "threat_type":      event_meta["threat_type"],
                    "risk_score":       0.0,
                    "risk_level":       "low",
                    "priority_score":   record.get("priority_score", "LOW"),
                    "confidence_score": 0.0,
                    "soc_action":       "monitor",
                    "attack_type":      record.get("attack_type", "Unknown"),
                    "threat_context":   "none",
                    "epss":             attributes.get("epss", 0.0),
                    "cvss_score":       cvss_from_cve,
                    "mitre_techniques": [],
                    "mitre_tactics":    [],
                    "iocs":             {},
                    "relations":        [],
                    "tags":             set(),
                    "source_list":      set(),
                    "first_seen":       collected_at,
                    "last_seen":        collected_at,
                }
                ev = self.events[group_id]

                # MITRE hérité depuis enrichissement
                for m in record.get("mitre_attack", []):
                    mid = m.get("id") if isinstance(m, dict) else m
                    if mid and mid not in ev["mitre_techniques"]:
                        ev["mitre_techniques"].append(mid)

                # Tag recent_threat pour CVE récente
                if cves:
                    try:
                        cve_obj = cves[0]
                        cid = cve_obj if isinstance(cve_obj, str) else cve_obj.get('id','')
                        year = int(str(cid).split('-')[1])
                        if year >= datetime.now().year - 1:
                            self.events[group_id]["tags"].add("recent_threat")
                    except:
                        pass

                # ── Contexte NLP spécifique DFIR Report ──────────────────
                if source.lower() == "dfir report":
                    nlp_ctx = attributes.get("nlp_analysis", {})
                    ev["threat_actors"]    = nlp_ctx.get("actor", [])
                    ev["targeted_sectors"] = nlp_ctx.get("victim", [])
                    ev["dfir_commands"]    = nlp_ctx.get("command", [])
                    ev["article_reference"] = (
                        record.get("references", [""])[0]
                        if record.get("references") else ""
                    )
                    # Tags : acteurs et commandes détectés
                    for actor in nlp_ctx.get("actor", []):
                        self.events[group_id]["tags"].add(f"actor:{actor.lower()}")
                    for cmd in nlp_ctx.get("command", [])[:5]:
                        self.events[group_id]["tags"].add(f"cmd:{cmd.lower()}")
                    for sector in nlp_ctx.get("victim", [])[:3]:
                        self.events[group_id]["tags"].add(f"target:{sector.lower()}")
                    self.events[group_id]["tags"].add("dfir-report")

            ev = self.events[group_id]
            ev["last_seen"] = max(ev["last_seen"], collected_at)
            ev["source_list"].add(source)
            for tag in record.get('tags', []):
                ev["tags"].add(tag)

            # ── IOC Processing & Relations ──
            sha256_val = None
            if source.lower() == 'malwarebazaar community api':
                sha256_val = attributes.get('sha256_hash') or next(
                    (i.get('value') for i in record.get('iocs', []) if i.get('type') == 'sha256'), None)

            cve_ref = None
            if cves:
                cve_obj = cves[0]
                cid     = cve_obj if isinstance(cve_obj, str) else cve_obj.get('id', '')
                cve_ref = cid

            for ioc_entry in record.get('iocs', []):
                val = ioc_entry.get('value')
                if not val:
                    continue
                typ = IOCCorrector.fix_type(val, ioc_entry.get('type', ''))
                if typ == 'url':
                    val = IOCCorrector.normalize_url(val)

                enrichment = ioc_entry.get('ioc_enrichment', {})
                relation   = enrichment.get('threat_type', 'related')

                # Relations URL → domain → IP
                if typ == 'url':
                    domain = self.get_domain_from_url(val)
                    if domain:
                        d_typ = IOCCorrector.fix_type(domain, 'domain')
                        self._add_ioc(group_id, domain, d_typ, 'url_contains_domain', source, enrichment, collected_at, record)
                        self._add_relation(group_id, val, domain, 'url_contains_domain')
                        ip = enrichment.get('ip') or enrichment.get('urlscan_ip') or attributes.get('ip')
                        if ip:
                            self._add_ioc(group_id, ip, 'ip', 'resolves_to', source, enrichment, collected_at, record)
                            self._add_relation(group_id, domain, ip, 'resolves_to')

                elif typ == 'domain':
                    ip = enrichment.get('ip') or enrichment.get('urlscan_ip') or attributes.get('ip')
                    if ip:
                        self._add_ioc(group_id, ip, 'ip', 'resolves_to', source, enrichment, collected_at, record)
                        self._add_relation(group_id, val, ip, 'resolves_to')

                # Hash links (malwarebazaar)
                if sha256_val and typ in ['md5', 'sha1', 'imphash', 'tlsh', 'ssdeep'] and val != sha256_val:
                    self._add_relation(group_id, sha256_val, val, "same_file_sample")

                # CVE ↔ IOC
                if cve_ref:
                    if typ in ['ip', 'domain', 'url']:
                        self._add_relation(group_id, cve_ref, val, "exploits")
                        self.events[group_id]["tags"].add("potential_exploitation_chain")
                    elif typ in ['md5', 'sha1', 'sha256']:
                        self._add_relation(group_id, val, cve_ref, "targets")

                orig_score  = ioc_entry.get('risk_score', 0.0)
                orig_action = ioc_entry.get('soc_action', 'monitor_quiet')
                self._add_ioc(group_id, val, typ, relation, source, enrichment, collected_at, record, orig_score, orig_action)

    def _add_ioc(self, group_id, value, ioc_type, relation, source, enrichment, timestamp, record, orig_score=0.0, orig_action='monitor_quiet'):
        ev_iocs = self.events[group_id]["iocs"]
        if value not in ev_iocs:
            ev_iocs[value] = {
                "type":       ioc_type,
                "value":      value,
                "relations":  set(),
                "sources":    set(),
                "enrichment": {},
                "risk_score": float(orig_score),
                "risk_level": RiskScorer._get_level(float(orig_score)),
                "soc_action": orig_action,
                "first_seen": timestamp,
                "last_seen":  timestamp,
            }
        ioc = ev_iocs[value]
        ioc["sources"].add(source)
        ioc["relations"].add(relation)
        ioc["last_seen"] = max(ioc["last_seen"], timestamp)
        if enrichment:
            ioc["enrichment"].update(enrichment)

        malware_family = (record.get('attributes', {}).get('malware_family') or
                          next((i.get('ioc_enrichment', {}).get('malware_family')
                                for i in record.get('iocs', [])
                                if i.get('ioc_enrichment', {}).get('malware_family')), None))
        score, level, action = RiskScorer.calculate_ioc_score(ioc, record.get('tags', []), malware_family)
        
        # Use the highest score (either calculated or original)
        if score > ioc["risk_score"]:
            ioc["risk_score"] = score
            ioc["risk_level"] = level
            ioc["soc_action"] = action
        elif float(orig_score) > ioc["risk_score"]:
             ioc["risk_score"] = float(orig_score)
             ioc["risk_level"] = RiskScorer._get_level(float(orig_score))
             ioc["soc_action"] = orig_action


    def _add_relation(self, group_id, source, target, rel_type):
        if not source or not target:
            return
        rel = {"source": source, "target": target, "type": rel_type}
        if rel not in self.events[group_id]["relations"]:
            self.events[group_id]["relations"].append(rel)

    def _validate_and_clean(self):
        logger.info("Phase 2 — Cleaning and Validating Events...")
        cleaned = []

        for group_id, event in self.events.items():
            if not event["iocs"] and event["event_type"] != "vulnerability":
                continue

            ioc_types = {ioc["type"] for ioc in event["iocs"].values()}
            has_ip      = 'ip' in ioc_types
            has_domain  = 'domain' in ioc_types
            has_malware = any(t in ioc_types for t in ['md5','sha1','sha256']) or event["event_type"] == 'malware'
            has_cve     = any(t in ioc_types for t in ['cve']) or event["event_type"] == "vulnerability"

            bonus = 0
            if has_ip and has_domain and has_malware:
                bonus = 20
                event["tags"].add("correlated_attack")

            # Sérialisation
            event["source_list"] = sorted(list(event["source_list"]))
            event["tags"]        = sorted(list(event["tags"]))

            ioc_list = []
            max_ioc_score = 0
            for val, ioc_data in event["iocs"].items():
                ioc_data["sources"]   = sorted(list(ioc_data["sources"]))
                ioc_data["relations"] = sorted(list(ioc_data["relations"]))
                
                # Metadata Cleaning: remove passer_par, paser, etc.
                if "enrichment" in ioc_data:
                    ioc_data["enrichment"] = {
                        k: v for k, v in ioc_data["enrichment"].items()
                        if not k.startswith(('passer_par', 'paser_', 'passser_'))
                    }
                
                ioc_list.append(ioc_data)
                if ioc_data["risk_score"] > max_ioc_score:
                    max_ioc_score = ioc_data["risk_score"]
            event["iocs"] = ioc_list


            # Threat context
            if has_cve and has_malware and len(ioc_list) > 2:
                if isinstance(event["tags"], list):
                    event["tags"].append("active_exploitation")
                else:
                    event["tags"].add("active_exploitation")

            # Correlation strength
            entity_diversity = len({ioc["type"] for ioc in ioc_list})
            event["correlation_strength"] = round(len(event["relations"]) * (1.5 if entity_diversity > 1 else 1.0), 1)

            # Confidence
            event["confidence_score"] = RiskScorer.calculate_confidence_score(event, event["source_list"])

            # Attack type fallback
            if event["attack_type"] in ("Unknown", None, ""):
                event["attack_type"] = RiskScorer.infer_attack_type(
                    event["event_type"], event["tags"], ioc_list)

            # MITRE bonus
            for tech in RiskScorer.get_mitre_bonus(event["attack_type"]):
                if tech not in event["mitre_techniques"]:
                    event["mitre_techniques"].append(tech)

            # Score final event (hors vulnerability — géré par CVSS)
            if event["event_type"] != "vulnerability":
                cve_bonus = 20 if has_cve else 0
                raw = min(max_ioc_score + bonus + cve_bonus, 100)

                # Si tous les IOCs ont score=0 (ex: Spamhaus, CINS sans VT/abuse),
                # utiliser source_confidence comme base minimale
                if raw == 0 and event["source_list"]:
                    src_key = event["source_list"][0].lower()
                    base_conf = next((v for k, v in RiskScorer.SOURCE_CONFIDENCE.items()
                                      if k in src_key or src_key in k), 50)
                    raw = round(base_conf * 0.3, 1)  # max 30 pts pour source seule
                if event["confidence_score"] < 60:
                    raw *= 0.8
                event["risk_score"] = round(raw, 1)
                event["risk_level"] = RiskScorer._get_level(event["risk_score"])

                if event.get("threat_type") == "threat_report":
                    tags_set = set(event["tags"]) if isinstance(event["tags"], list) else event["tags"]
                    if "ransomware" in tags_set and "recent_threat" in tags_set:
                        event["risk_score"] = max(event["risk_score"], 65.0)
                        event["risk_level"] = RiskScorer._get_level(event["risk_score"])
                        event["priority_score"] = "HIGH"
                        event["soc_action"]     = "investigate"

                s = event["risk_score"]
                if s >= 90:
                    event["priority_score"] = "CRITICAL"
                    event["soc_action"]     = "incident_response" if (has_cve and has_malware) else "escalate"
                elif s >= 70:
                    event["priority_score"] = "HIGH"
                    event["soc_action"]     = "investigate"
                elif s >= 40:
                    event["priority_score"] = "MEDIUM"
                    event["soc_action"]     = "monitor"
                else:
                    event["priority_score"] = "LOW"
                    event["soc_action"]     = "monitor"
            else:
                # Pour les CVE : cvss depuis event stocké OU depuis iocs
                cvss = float(event.get("cvss_score", 0) or 0)
                if cvss == 0:
                    for ioc in ioc_list:
                        c = ioc.get("enrichment", {}).get("cvss_score", 0) or 0
                        try: cvss = max(cvss, float(c))
                        except: pass
                event["risk_score"] = round(cvss * 10, 1)
                if cvss >= 9.0:
                    event["priority_score"] = "CRITICAL"
                    event["soc_action"]     = "escalate"
                elif cvss >= 7.0:
                    event["priority_score"] = "HIGH"
                    event["soc_action"]     = "investigate"
                elif cvss >= 4.0:
                    event["priority_score"] = "MEDIUM"
                    event["soc_action"]     = "monitor"
                else:
                    event["priority_score"] = "LOW"
                    event["soc_action"]     = "monitor_quiet"
                event["risk_level"] = RiskScorer._get_level(event["risk_score"])

            # Tags finaux
            tags_set = set(event["tags"]) if isinstance(event["tags"], list) else event["tags"]
            tags_set.add("soc_enriched")
            event["tags"] = sorted(list(tags_set))

            # Déduplication relations
            seen, unique_rels = set(), []
            for rel in event["relations"]:
                rid = f"{rel['source']}-{rel['target']}-{rel['type']}"
                if rid not in seen:
                    unique_rels.append(rel)
                    seen.add(rid)
            event["relations"] = unique_rels

            cleaned.append(event)

        return cleaned

    def finalize_and_save(self):
        if not self.has_new_data:
            logger.info("No new data processed. Skipping new correlation file generation.")
            return
        if not self.events:
            logger.info("No events to save.")
            return
        cleaned = self._validate_and_clean()
        timestamp = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        output_file = os.path.join(self.output_dir, f"correlation_file_{timestamp}.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned, f, indent=4, ensure_ascii=False)

        # Résumé
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for ev in cleaned:
            p = ev.get("priority_score","LOW")
            counts[p] = counts.get(p,0)+1
        logger.info("=" * 55)
        logger.info(f"  EVENTS GÉNÉRÉS  : {len(cleaned)}")
        logger.info(f"  CRITICAL        : {counts['CRITICAL']}")
        logger.info(f"  HIGH            : {counts['HIGH']}")
        logger.info(f"  MEDIUM          : {counts['MEDIUM']}")
        logger.info(f"  LOW             : {counts['LOW']}")
        logger.info(f"  OUTPUT          : {output_file}")
        logger.info("=" * 55)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CTI Correlation Pre-MISP")
    parser.add_argument("-i", "--input",  default=None, help="Répertoire input (enriched JSONs)")
    parser.add_argument("-o", "--output", default=None, help="Répertoire output (correlated events)")
    args = parser.parse_args()

    BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    INPUT_DIR  = args.input  or os.path.join(BASE_DIR, "output_enrichment")
    OUTPUT_DIR = args.output or os.path.join(BASE_DIR, "output_correlation")

    correlator = ThreatCorrelator(INPUT_DIR, OUTPUT_DIR)
    correlator.process_files()
    correlator.finalize_and_save()