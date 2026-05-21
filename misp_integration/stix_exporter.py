import json
import os
import sys
import uuid
from datetime import datetime, timezone

# Force UTF-8 stdout on Windows to avoid cp1252 UnicodeEncodeError
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT_FILE  = os.path.join(BASE_DIR, "output_correlation", "correlated_events_soc_enriched.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "output_correlation", "stix_export.json")

# ─────────────────────────────────────────────────────────
#  Mappages
# ─────────────────────────────────────────────────────────
# attack_type -> liste de malware_types STIX (plus précis que 1 seul type)
ATTACK_TYPE_TO_MALWARE_TYPES = {
    # Malware
    "Botnet":           ["bot", "trojan"],
    "RAT":              ["remote-access-trojan", "backdoor"],
    "Stealer":          ["spyware", "credential-stealer", "keylogger"],
    "Ransomware":       ["ransomware"],
    "Dropper":          ["dropper", "downloader"],
    "Wiper":            ["wiper"],
    "Cryptominer":      ["resource-exploitation"],
    "ExploitKit":       ["exploit-kit"],
    "Rootkit":          ["rootkit", "backdoor"],
    "Packer":           ["trojan"],
    "Backdoor":         ["backdoor"],
    "Bootkit":          ["bootkit", "rootkit"],
    "Webshell":         ["webshell", "backdoor"],
    "Adware":           ["adware"],
    "Spyware":          ["spyware", "screen-capture"],
    "WidespreadMalware":["trojan"],
    # Phishing
    "Phishing":         ["trojan"],
    "Credential":       ["spyware", "credential-stealer"],
    "BEC":              ["trojan"],
    "Spearphish":       ["trojan"],
    "Smishing":         ["trojan"],
    # Vulnerability
    "RCE":              ["exploit-kit"],
    "LPE":              ["exploit-kit"],
    "SQLi":             ["exploit-kit"],
    "XSS":              ["exploit-kit"],
    "SSRF":             ["exploit-kit"],
    "DoS":              ["ddos"],
    "AuthBypass":       ["exploit-kit"],
    "ZeroDay":          ["exploit-kit"],
    "Exploit":          ["exploit-kit"],
    # Fallback
    "Unknown":          ["unknown"],
    "Other":            ["unknown"],
}

# malware_family -> (galaxy MISP, cluster, malware_types spécifiques)
# MISP utilisera le label misp-galaxy:malpedia="<cluster>" pour identifier la famille exacte
MALWARE_FAMILY_MAP = {
    # Botnets bancaires
    "qakbot":         ("malpedia", "QakBot",          ["trojan", "banker", "bot"]),
    "emotet":         ("malpedia", "Emotet",           ["trojan", "banker", "spam-bot"]),
    "trickbot":       ("malpedia", "TrickBot",         ["trojan", "banker"]),
    "dridex":         ("malpedia", "Dridex",           ["trojan", "banker"]),
    "icedid":         ("malpedia", "IcedID",           ["trojan", "banker"]),
    # RATs
    "quasar rat":     ("malpedia", "Quasar RAT",       ["remote-access-trojan"]),
    "remcos":         ("malpedia", "Remcos",           ["remote-access-trojan"]),
    "njrat":          ("malpedia", "njRAT",            ["remote-access-trojan"]),
    "asyncrat":       ("malpedia", "AsyncRAT",         ["remote-access-trojan"]),
    "havoc":          ("malpedia", "Havoc",            ["remote-access-trojan"]),
    "cobalt strike":  ("malpedia", "Cobalt Strike",    ["remote-access-trojan"]),
    # Stealers
    "unknown stealer":("malpedia", "Unknown Stealer",  ["spyware", "credential-stealer"]),
    "redline":        ("malpedia", "RedLine Stealer",  ["spyware", "credential-stealer"]),
    "lumma":          ("malpedia", "LummaC2",          ["spyware", "credential-stealer"]),
    "agenttesla":     ("malpedia", "AgentTesla",       ["spyware", "credential-stealer"]),
    "formbook":       ("malpedia", "FormBook",         ["spyware", "credential-stealer"]),
    "vidar":          ("malpedia", "Vidar",            ["spyware", "credential-stealer"]),
    # Ransomware
    "lockbit":        ("malpedia", "LockBit",          ["ransomware"]),
    "ryuk":           ("malpedia", "Ryuk",             ["ransomware"]),
    "conti":          ("malpedia", "Conti",            ["ransomware"]),
    "blackcat":       ("malpedia", "BlackCat",         ["ransomware"]),
    "alphv":          ("malpedia", "BlackCat",         ["ransomware"]),
    "yurei":          ("malpedia", "Yurei",            ["ransomware"]),
    # Droppers / Loaders
    "clearfake":      ("malpedia", "ClearFake",        ["dropper"]),
    "bumblebee":      ("malpedia", "Bumblebee",        ["dropper"]),
    "guloader":       ("malpedia", "GuLoader",         ["dropper"]),
    # Botnets IoT
    "mirai":          ("malpedia", "Mirai",            ["worm", "bot"]),
    "mozi":           ("malpedia", "Mozi",             ["worm", "bot"]),
    "gafgyt":         ("malpedia", "BASHLITE",         ["worm", "bot"]),
}
# backward compat
ATTACK_TYPE_TO_MALWARE_TYPE = {k: v[0] for k, v in {
    "Botnet": ("trojan",), "RAT": ("remote-access-trojan",),
    "Stealer": ("spyware",), "Ransomware": ("ransomware",),
    "Dropper": ("dropper",), "Wiper": ("worm",),
}.items()}

ATTACK_TYPE_TO_KILL_CHAIN = {
    # Malware
    "Botnet":           [("mitre-attack", "resource-development"),
                         ("mitre-attack", "command-and-control"),
                         ("mitre-attack", "execution")],
    "RAT":              [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution"),
                         ("mitre-attack", "persistence"),
                         ("mitre-attack", "command-and-control")],
    "Stealer":          [("mitre-attack", "credential-access"),
                         ("mitre-attack", "collection"),
                         ("mitre-attack", "exfiltration")],
    "Ransomware":       [("mitre-attack", "execution"),
                         ("mitre-attack", "impact")],
    "Dropper":          [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution"),
                         ("mitre-attack", "defense-evasion")],
    "Wiper":            [("mitre-attack", "execution"),
                         ("mitre-attack", "impact")],
    "Cryptominer":      [("mitre-attack", "execution"),
                         ("mitre-attack", "impact")],
    "ExploitKit":       [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution")],
    "Rootkit":          [("mitre-attack", "persistence"),
                         ("mitre-attack", "privilege-escalation"),
                         ("mitre-attack", "defense-evasion")],
    "Packer":           [("mitre-attack", "defense-evasion"),
                         ("mitre-attack", "execution")],
    "Backdoor":         [("mitre-attack", "persistence"),
                         ("mitre-attack", "command-and-control")],
    "Bootkit":          [("mitre-attack", "persistence"),
                         ("mitre-attack", "privilege-escalation")],
    "Webshell":         [("mitre-attack", "persistence"),
                         ("mitre-attack", "execution"),
                         ("mitre-attack", "command-and-control")],
    "Adware":           [("mitre-attack", "execution"),
                         ("mitre-attack", "impact")],
    "Spyware":          [("mitre-attack", "collection"),
                         ("mitre-attack", "credential-access")],
    "WidespreadMalware":[("mitre-attack", "execution"),
                         ("mitre-attack", "command-and-control")],
    # Phishing
    "Phishing":         [("mitre-attack", "initial-access"),
                         ("mitre-attack", "credential-access")],
    "Credential":       [("mitre-attack", "credential-access"),
                         ("mitre-attack", "collection"),
                         ("mitre-attack", "exfiltration")],
    "BEC":              [("mitre-attack", "initial-access"),
                         ("mitre-attack", "collection")],
    "Spearphish":       [("mitre-attack", "initial-access"),
                         ("mitre-attack", "credential-access")],
    "Smishing":         [("mitre-attack", "initial-access"),
                         ("mitre-attack", "credential-access")],
    # Vulnerability
    "RCE":              [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution")],
    "LPE":              [("mitre-attack", "privilege-escalation")],
    "SQLi":             [("mitre-attack", "initial-access"),
                         ("mitre-attack", "credential-access")],
    "XSS":              [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution")],
    "SSRF":             [("mitre-attack", "initial-access"),
                         ("mitre-attack", "discovery")],
    "DoS":              [("mitre-attack", "impact")],
    "AuthBypass":       [("mitre-attack", "initial-access"),
                         ("mitre-attack", "privilege-escalation")],
    "ZeroDay":          [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution")],
    "Exploit":          [("mitre-attack", "initial-access"),
                         ("mitre-attack", "execution")],
    # Fallback
    "Unknown":          [("mitre-attack", "execution")],
    "Other":            [("mitre-attack", "execution")],
}

INDICATOR_TYPE_MAP = {
    "CRITICAL": "malicious-activity",
    "HIGH":     "malicious-activity",
    "MEDIUM":   "anomalous-activity",
    "LOW":      "anomalous-activity",
}

RELATIONSHIP_TYPES = {
    # (source_type, target_type) -> relationship_type
    ("indicator",        "malware"):       "indicates",
    ("indicator",        "campaign"):      "indicates",
    ("indicator",        "vulnerability"): "indicates",
    ("indicator",        "infrastructure"):"indicates",
    ("malware",          "attack-pattern"):"uses",
    ("campaign",         "malware"):       "uses",
    ("campaign",         "identity"):      "targets",
    ("malware",          "vulnerability"): "exploits",
    ("campaign",         "threat-actor"):  "attributed-to",
}


class STIXExporter:
    """Exporte correlated_events_soc_enriched.json → STIX 2.1 bundle complet."""

    def __init__(self):
        self.identity_id = f"identity--{uuid.uuid4()}"
        self.objects      = []
        self._now_str     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self._add_identity()

    # ── Helpers ─────────────────────────────────────────
    def _ts(self, iso_str=None):
        if iso_str:
            try:
                s = iso_str.replace("+00:00", "Z").replace(" ", "T")
                if "." not in s:
                    s = s.replace("Z", ".000000Z")
                # STIX 2.1 exige le suffixe Z
                if not s.endswith("Z") and "+" not in s:
                    s += "Z"
                return s
            except Exception:
                pass
        return self._now_str

    def _stix_pattern(self, ioc_type, value):
        t = ioc_type.lower()
        v = str(value).replace("'", "\\'")
        m = {
            "ip":       f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{v}']" if "/" in v else f"[ipv4-addr:value = '{v}']",
            "ipv4":     f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{v}']" if "/" in v else f"[ipv4-addr:value = '{v}']",
            "ipv6":     f"[ipv6-addr:value = '{v}']",
            "domain":   f"[domain-name:value = '{v}']",
            "hostname": f"[domain-name:value = '{v}']",
            "url":      f"[url:value = '{v}']",
            "md5":      f"[file:hashes.'MD5' = '{v}']",
            "sha1":     f"[file:hashes.'SHA-1' = '{v}']",
            "sha256":   f"[file:hashes.'SHA-256' = '{v}']",
            "sha3_384": f"[file:hashes.'SHA3-384' = '{v}']",
            "hash":     f"[file:hashes.'MD5' = '{v}']",
            "cve":      f"[vulnerability:name = '{v}']",
        }
        return m.get(t, f"[x-unknown:value = '{v}']")

    def _mitre_refs(self, techniques):
        refs = []
        for t in (techniques or []):
            if t and t != "Unknown":
                refs.append({
                    "source_name": "mitre-attack",
                    "external_id": t,
                    "url": f"https://attack.mitre.org/techniques/{t}/"
                })
        return refs

    def _cve_refs(self, group_id):
        """Construit les refs CVE + NVD depuis le group_id."""
        cve_id = group_id.replace("CVE-", "", 1) if group_id.startswith("CVE-CVE-") else group_id.replace("CVE-", "", 1)
        # Normaliser : CVE-CVE-2002-0367 -> CVE-2002-0367
        if cve_id.startswith("CVE-"):
            pass
        else:
            cve_id = "CVE-" + cve_id
        return [
            {"source_name": "cve",  "external_id": cve_id},
            {"source_name": "nvd",  "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        ]

    def _kill_chain(self, attack_type):
        phases = ATTACK_TYPE_TO_KILL_CHAIN.get(attack_type, [])
        return [{"kill_chain_name": kc, "phase_name": ph} for kc, ph in phases]

    def _ioc_description(self, ioc, event):
        """Description enrichie de l'IOC — toutes les données disponibles."""
        e     = ioc.get("enrichment", {})
        lines = []

        # Priorité et scoring
        ioc_prio = ioc.get("priority_score", event.get("priority_score", "LOW"))
        lines.append(f"IOC Priority : {ioc_prio} | Risk Score : {ioc.get('risk_score', 0)}")
        lines.append(f"SOC Action   : {ioc.get('soc_action', 'monitor').upper()}")
        conf = ioc.get("confidence_label") or event.get("confidence_score","")
        if conf:
            lines.append(f"Confidence   : {conf}")

        # Contexte menace
        atk = ioc.get("attack_type") or event.get("attack_type","")
        if atk and atk not in ("Other","Unknown"):
            lines.append(f"Attack Type  : {atk}")
        family = ioc.get("malware_family") or e.get("malware_family","")
        if family:
            lines.append(f"Malware Family: {family}")
        tlp = ioc.get("tlp") or e.get("tlp","TLP:CLEAR")
        lines.append(f"TLP          : {tlp}")

        # Géolocalisation
        country = ioc.get("country") or e.get("country") or e.get("countryCode","")
        isp     = ioc.get("isp") or e.get("isp","")
        asn     = ioc.get("asn") or e.get("asn","")
        as_own  = ioc.get("as_owner") or e.get("as_owner","")
        if country: lines.append(f"Country      : {country}")
        if isp:     lines.append(f"ISP          : {isp}")
        if asn:     lines.append(f"ASN          : {asn} ({as_own})")

        # VirusTotal
        vt_mal = ioc.get("vt_malicious_count")
        if vt_mal is None: vt_mal = e.get("vt_malicious_count")
        vt_tot = e.get("vt_total_engines","?")
        if vt_mal is not None:
            lines.append(f"VirusTotal   : {vt_mal}/{vt_tot} malicious engines")
            if e.get("vt_reputation") is not None:
                lines.append(f"VT Reputation: {e['vt_reputation']}")
            if e.get("vt_tags"):
                lines.append(f"VT Tags      : {', '.join(e['vt_tags'])}")

        # AbuseIPDB
        abuse = ioc.get("abuse_score")
        if abuse is None: abuse = e.get("abuseConfidenceScore")
        if abuse is not None:
            reports = e.get("totalReports", 0)
            lines.append(f"AbuseIPDB    : {abuse}% confidence ({reports} reports)")
            if e.get("lastReportedAt"):
                lines.append(f"Last Reported: {e['lastReportedAt']}")

        # URLScan
        urlscan_rep  = ioc.get("urlscan_report")  or e.get("urlscan_report_url","")
        urlscan_shot = ioc.get("urlscan_screenshot") or e.get("urlscan_screenshot_url","")
        risk_flag    = ioc.get("risk_flag") or e.get("risk_flag","")
        typosquat    = ioc.get("typosquat_flag")
        susp_kw      = e.get("suspicious_keywords",[])
        if urlscan_rep:  lines.append(f"URLScan      : {urlscan_rep}")
        if urlscan_shot: lines.append(f"Screenshot   : {urlscan_shot}")
        if risk_flag:    lines.append(f"URLScan Risk : {risk_flag.upper()}")
        if typosquat:    lines.append("Typosquatting: detected")
        if susp_kw:      lines.append(f"Susp. Keywords: {', '.join(susp_kw)}")

        # Statut (feodotracker C2)
        status = e.get("status","")
        port   = e.get("port","")
        if status: lines.append(f"C2 Status    : {status.upper()}")
        if port:   lines.append(f"Port         : {port}")

        # MalwareBazaar hashes
        for h in ("sha1","sha3_384","tlsh","ssdeep","imphash"):
            if e.get(h): lines.append(f"{h.upper():<12}: {e[h]}")
        if e.get("file_size"):
            lines.append(f"File Size    : {e['file_size']} bytes")
        if e.get("reporter"):
            lines.append(f"Reporter     : {e['reporter']}")
        if e.get("intel_downloads"):
            lines.append(f"Downloads    : {e['intel_downloads']}")

        # Sources
        srcs = ioc.get("sources",[])
        if srcs: lines.append(f"Sources      : {', '.join(srcs)}")

        # First/last seen
        if ioc.get("first_seen"): lines.append(f"First Seen   : {ioc['first_seen']}")
        if ioc.get("last_seen"):  lines.append(f"Last Seen    : {ioc['last_seen']}")

        return "\n".join(lines)

    def _event_description(self, event):
        lines = [
            f"Priority     : {event.get('priority_score','LOW')}",
            f"Risk Score   : {event.get('risk_score',0)}",
            f"SOC Action   : {event.get('soc_action','monitor').upper()}",
            f"Attack Type  : {event.get('attack_type','Unknown')}",
            f"Confidence   : {event.get('confidence_score',0)}%",
            f"Event Type   : {event.get('event_type','')}",
        ]
        if event.get("source_list"):
            lines.append(f"Sources      : {', '.join(event['source_list'])}")
        if event.get("first_seen"):
            lines.append(f"First Seen   : {event['first_seen']}")
        if event.get("last_seen"):
            lines.append(f"Last Seen    : {event['last_seen']}")
        if event.get("correlation_strength"):
            lines.append(f"Corr. Strength: {event['correlation_strength']}")
        return "\n".join(lines)

    def _add_identity(self):
        self.objects.append({
            "type":           "identity",
            "spec_version":   "2.1",
            "id":             self.identity_id,
            "created":        self._now_str,
            "modified":       self._now_str,
            "name":           "SOC-PFE-CTI",
            "identity_class": "organization",
            "description":    "Plateforme CTI Interne SOC",
        })

    # ── Création des objets STIX principaux ─────────────
    def _make_main_object(self, event, now):
        etype    = event.get("event_type", "suspicious")
        at       = event.get("attack_type", "Other")
        ext_refs = self._mitre_refs(event.get("mitre_techniques", []))
        labels   = [t for t in event.get("tags", []) if t]
        ts_first = self._ts(event.get("first_seen"))
        ts_last  = self._ts(event.get("last_seen"))

        base = {
            "spec_version":    "2.1",
            "created_by_ref":  self.identity_id,
            "created":         now,
            "modified":        now,
            "name":            event.get("event_name", event.get("group_id")),
            "description":     self._event_description(event),
            "labels":          labels,
            "confidence":      int(event.get("confidence_score", 0)),
            "external_references": ext_refs,
            "x_soc_priority":  event.get("priority_score"),
            "x_soc_risk":      event.get("risk_score"),
            "x_soc_action":    event.get("soc_action"),
            "x_soc_group_id":  event.get("group_id"),
        }

        # CAMPAIGN- toujours campaign même si event_type="malware"
        if event.get("group_id", "").startswith("CAMPAIGN-") and etype != "phishing":
            etype = "campaign"

        if etype == "malware":
            mid = f"malware--{uuid.uuid4()}"
            kc  = self._kill_chain(at) or [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]
            # Chercher la famille malware : IOCs > group_id > tags
            family_raw = ""
            for ioc in event.get("iocs", []):
                fam = ioc.get("malware_family") or ioc.get("enrichment", {}).get("malware_family", "")
                if fam:
                    family_raw = fam
                    break
            # Fallback: extraire depuis group_id (MAL-QAKBOT -> qakbot -> QakBot)
            if not family_raw:
                gid = event.get("group_id", "")
                if gid.startswith("MAL-"):
                    family_raw = gid.replace("MAL-", "").replace("-", " ").title().strip()
            # Fallback: extraire depuis les tags (yurei ransomware -> Yurei)
            if not family_raw:
                for tag in event.get("tags", []):
                    parts = tag.lower().split()
                    if len(parts) >= 2 and any(kw in parts for kw in ["ransomware","botnet","rat","stealer","trojan","worm","dropper"]):
                        candidate = parts[0].title()
                        if candidate.lower() in MALWARE_FAMILY_MAP:
                            family_raw = candidate
                            break
            # Résoudre les malware_types et galaxy label depuis la famille
            family_key = family_raw.lower().strip()
            if family_key in MALWARE_FAMILY_MAP:
                galaxy, cluster, mtypes = MALWARE_FAMILY_MAP[family_key]
                galaxy_label = f'misp-galaxy:{galaxy}="{cluster}"'
                # Ajouter le label galaxy dans les labels de l objet
                if galaxy_label not in base["labels"]:
                    base["labels"].append(galaxy_label)
                # Ajouter aussi le nom exact de la famille comme label
                base["labels"].append(f"malware-family:{cluster.lower().replace(' ', "-")}")
            else:
                # Fallback depuis attack_type
                mtypes = ATTACK_TYPE_TO_MALWARE_TYPES.get(at, ["trojan"])
                if family_raw:
                    base["labels"].append(f"malware-family:{family_raw.lower().replace(' ', "-")}")

            # Description enrichie avec la famille
            if family_raw and family_raw not in base["description"]:
                base["description"] = "Malware Family: " + family_raw + "\n" + base["description"]


            base.update({
                "type":              "malware",
                "id":                mid,
                "is_family":         True,
                "malware_types":     mtypes,
                "kill_chain_phases": kc,
                "first_seen":        ts_first,
                "last_seen":         ts_last,
            })

        elif etype == "vulnerability":
            mid = f"vulnerability--{uuid.uuid4()}"
            cve_refs = self._cve_refs(event.get("group_id",""))
            base.update({
                "type":               "vulnerability",
                "id":                 mid,
                "external_references": cve_refs + ext_refs,
                "x_cvss_score":       event.get("cvss_score", 0),
            })

        elif etype == "phishing":
            mid = f"campaign--{uuid.uuid4()}"
            base.update({
                "type":      "campaign",
                "id":        mid,
                "objective": "Credential harvesting / Phishing",
                "first_seen": ts_first,
                "last_seen":  ts_last,
            })

        elif event.get("group_id","").startswith("CAMPAIGN-"):
            mid = f"campaign--{uuid.uuid4()}"
            base.update({
                "type":       "campaign",
                "id":         mid,
                "objective":  f"Threat campaign: {at}",
                "first_seen": ts_first,
                "last_seen":  ts_last,
            })

        else:
            mid = f"infrastructure--{uuid.uuid4()}"
            base.update({
                "type":                "infrastructure",
                "id":                  mid,
                "infrastructure_types": ["malicious-server"],
            })

        return mid, base

    def _make_indicator(self, ioc, event, now):
        ioc_type = ioc.get("type","")
        value    = ioc.get("value","")
        priority = ioc.get("priority_score") or event.get("priority_score","LOW")
        ind_type = INDICATOR_TYPE_MAP.get(priority, "anomalous-activity")
        ts_valid = self._ts(ioc.get("first_seen") or event.get("first_seen"))

        # External refs : MITRE depuis IOC ou event
        mitre = ioc.get("mitre_techniques") or event.get("mitre_techniques",[])
        ext_refs = self._mitre_refs(mitre)
        urlscan  = ioc.get("urlscan_report") or ioc.get("enrichment",{}).get("urlscan_report_url","")
        if urlscan:
            ext_refs.append({"source_name": "urlscan", "url": urlscan})

        # Labels IOC
        labels = [f"soc:action={ioc.get('soc_action','monitor')}"]
        tlp = ioc.get("tlp") or ioc.get("enrichment",{}).get("tlp","")
        if tlp: labels.append(tlp)
        fam = ioc.get("malware_family") or ioc.get("enrichment",{}).get("malware_family","")
        if fam: labels.append(f"malware-family:{fam.lower()}")
        country = ioc.get("country") or ioc.get("enrichment",{}).get("country","")
        if country: labels.append(f"country:{country.lower()}")
        rf = ioc.get("risk_flag") or ioc.get("enrichment",{}).get("risk_flag","")
        if rf == "high": labels.append("urlscan:risk=high")
        if ioc.get("typosquat_flag") or ioc.get("enrichment",{}).get("typosquat_flag"):
            labels.append("urlscan:typosquat=true")

        ind_id = f"indicator--{uuid.uuid4()}"
        indicator = {
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              ind_id,
            "created_by_ref":  self.identity_id,
            "created":         now,
            "modified":        now,
            "name":            f"{ioc_type.upper()} - {value}",
            "description":     self._ioc_description(ioc, event),
            "indicator_types": [ind_type],
            "pattern":         self._stix_pattern(ioc_type, value),
            "pattern_type":    "stix",
            "valid_from":      ts_valid,
            "confidence":      int(ioc.get("source_confidence") or event.get("confidence_score", 0)),
            "labels":          labels,
            "external_references": ext_refs,
            "x_ioc_risk_score":  ioc.get("risk_score", 0),
            "x_ioc_priority":    priority,
            "x_ioc_risk_level":  ioc.get("risk_level","low"),
            "x_ioc_sources":     ioc.get("sources",[]),
            "x_ioc_relations":   ioc.get("relations",[]),
        }
        return ind_id, indicator

    def _make_relationship(self, src_id, tgt_id, rel_type, now):
        return {
            "type":              "relationship",
            "spec_version":      "2.1",
            "id":                f"relationship--{uuid.uuid4()}",
            "created_by_ref":    self.identity_id,
            "created":           now,
            "modified":          now,
            "relationship_type": rel_type,
            "source_ref":        src_id,
            "target_ref":        tgt_id,
        }

    def _make_attack_pattern(self, technique, now):
        ap_id = f"attack-pattern--{uuid.uuid4()}"
        return ap_id, {
            "type":          "attack-pattern",
            "spec_version":  "2.1",
            "id":            ap_id,
            "created_by_ref": self.identity_id,
            "created":       now,
            "modified":      now,
            "name":          technique,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique,
                "url": f"https://attack.mitre.org/techniques/{technique}/"
            }]
        }

    # ── Conversion principale ────────────────────────────
    def convert_all(self, events_data):
        for event in events_data:
            now   = self._ts(event.get("first_seen")) or self._now_str
            etype = event.get("event_type", "suspicious")

            # Objet principal
            main_id, main_obj = self._make_main_object(event, now)
            self.objects.append(main_obj)
            event_refs = [main_id]

            # Attack patterns depuis MITRE techniques (max 3)
            ap_ids = []
            for tech in event.get("mitre_techniques", [])[:3]:
                if tech and tech != "Unknown":
                    ap_id, ap_obj = self._make_attack_pattern(tech, now)
                    self.objects.append(ap_obj)
                    ap_ids.append(ap_id)
                    # malware/campaign uses attack-pattern
                    if main_obj["type"] in ("malware","campaign"):
                        rel = self._make_relationship(main_id, ap_id, "uses", now)
                        self.objects.append(rel)
                        event_refs.append(ap_id)
                        event_refs.append(rel["id"])

            # Indicateurs
            for ioc in event.get("iocs", []):
                ind_id, ind_obj = self._make_indicator(ioc, event, now)
                self.objects.append(ind_obj)
                event_refs.append(ind_id)

                # indicator indicates main_object
                rel = self._make_relationship(ind_id, main_id, "indicates", now)
                self.objects.append(rel)
                event_refs.append(rel["id"])

            # Relations supplémentaires depuis event.relations
            for rel_data in event.get("relations", []):
                # On ne peut pas faire de relations STIX sans résoudre les IDs
                # On stocke en custom property sur le report
                pass

            # Report groupant tout
            rep_id = f"report--{uuid.uuid4()}"
            report = {
                "type":          "report",
                "spec_version":  "2.1",
                "id":            rep_id,
                "created_by_ref": self.identity_id,
                "created":       now,
                "modified":      now,
                "published":     now,
                "name":          f"SOC Report: {event.get('event_name', event.get('group_id'))}",
                "description":   self._event_description(event),
                "report_types":  ["threat-report"],
                "object_refs":   list(dict.fromkeys(event_refs)),
                "labels":        [t for t in event.get("tags",[]) if t],
                "x_soc_sources": event.get("source_list",[]),
                "x_correlation_strength": event.get("correlation_strength",0),
            }
            self.objects.append(report)

    def export(self, input_file=None, output_file=None):
        src = input_file or INPUT_FILE
        dst = output_file or OUTPUT_FILE

        if not os.path.exists(src):
            print(f"Erreur : {src} introuvable.")
            return False

        with open(src, "r", encoding="utf-8") as f:
            data = json.load(f)

        print(f"Conversion de {len(data)} evenements -> STIX 2.1 ...")
        self.convert_all(data)

        bundle = {
            "type":    "bundle",
            "id":      f"bundle--{uuid.uuid4()}",
            "x_soc_export_date": self._now_str,
            "objects": self.objects,
        }

        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=4, ensure_ascii=False)

        # Stats
        types = {}
        for o in self.objects:
            t = o["type"]
            types[t] = types.get(t, 0) + 1

        print(f"\nBundle STIX généré : {dst}")
        print(f"Total objets : {len(self.objects)}")
        for t, n in sorted(types.items()):
            print(f"  {t:<22} : {n}")
        return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Export STIX 2.1 depuis correlated_events")
    parser.add_argument("-i", "--input",  help="Fichier JSON corrélé (input)")
    parser.add_argument("-o", "--output", help="Fichier STIX bundle (output)")
    args = parser.parse_args()

    exporter = STIXExporter()
    exporter.export(input_file=args.input, output_file=args.output)