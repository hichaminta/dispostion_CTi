import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import sys
import re
import ipaddress
from datetime import datetime, timezone

EXTRACTORS_DIR = os.path.dirname(os.path.abspath(__file__))
if EXTRACTORS_DIR not in sys.path:
    sys.path.append(EXTRACTORS_DIR)
from base_extractor import BaseExtractor

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
except Exception as e:
    nlp = None
    print(f"Warning: Failed to load spaCy model in dfir_report_extractor: {e}")

def _extract_nlp_context(text):
    """
    Utilise spaCy pour extraire les entités sémantiques de l'article après nettoyage du HTML
    et les classifie selon les sections demandées : actor, victim, command, other.
    """
    if not nlp or not text or len(text) < 10:
        return {
            "actor": [],
            "victim": [],
            "command": [],
            "other": []
        }
    
    # 1. Supprimer le contenu des balises style et script
    clean_text = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    # 2. Supprimer toutes les balises HTML restantes
    clean_text = re.sub(r'<[^>]+>', ' ', clean_text)
    # 3. Remplacer les entités HTML courantes
    clean_text = clean_text.replace('&quot;', '"').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    # 4. Supprimer les attributs de blocs Elementor / WordPress
    clean_text = re.sub(r'\b(?:wp-context|wp-init|wp-key|width|height|class|alt|id|style|src|href)\s*=\s*"[^"]*"', ' ', clean_text, flags=re.IGNORECASE)
    clean_text = re.sub(r'\b(?:wp-context|wp-init|wp-key|width|height|class|alt|id|style|src|href)\s*=\s*\'[^\']*\'', ' ', clean_text, flags=re.IGNORECASE)
    # 5. Supprimer les lignes orphelines contenant des résidus JSON ou d'attributs
    clean_text = re.sub(r'\{&quot;.*?&quot;\}', ' ', clean_text)
    
    doc = nlp(clean_text[:100000])
    
    actors = []
    victims = []
    commands = []
    others = []
    technologies = []

    # Regex pour extraire les versions de logiciels/technologies (ex: v2.15.0, Log4j 2.x, Apache 2.4.51)
    _VERSION_PAT = re.compile(
        r'\b([A-Za-z][A-Za-z0-9_\-\.]{2,30})\s+(v?\d+\.\d+(?:\.\d+){0,3}(?:[\-\._][\w]+)?)',
        re.IGNORECASE
    )
    # Mots indiquant du contexte réseau (pas un nom de logiciel)
    _NET_CONTEXT_WORDS = {
        "address", "addresses", "source", "destination", "src", "dst", "host",
        "from", "to", "with", "via", "over", "country", "network", "server",
        "port", "spray", "kingdom", "belgium", "access", "scan", "atomic",
        "round", "version", "build", "number", "count", "total", "found", "running"
    }
    _IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}')
    for vmatch in _VERSION_PAT.finditer(clean_text):
        tech_name = vmatch.group(1).strip()
        tech_ver  = vmatch.group(2).strip()
        # Exclure si le "nom" est un mot de contexte réseau
        if tech_name.lower() in _NET_CONTEXT_WORDS:
            continue
        # Exclure si la "version" ressemble à une IP
        if _IP_PATTERN.search(tech_ver):
            continue
        tech_entry = f"{tech_name} {tech_ver}"
        if tech_entry not in technologies and len(tech_name) > 2:
            technologies.append(tech_entry)

    # Mots-cles de bruit a ne pas taguer
    _TAG_NOISE = re.compile(
        r'share\s+on|linkedin|facebook|whatsapp|twitter|subscribe|newsletter|'
        r'annually|monthly|weekly|first|second|third|\d{4}$|^\d+$',
        re.IGNORECASE
    )
    
    # Détection par Regex des commandes / outils connus
    cmd_regex = re.compile(
        r'\b(cmd(?:\.exe)?|powershell(?:\.exe)?|whoami|net\s+user|net\s+localgroup|net\s+use|ipconfig|systeminfo|sc\s+query|vssadmin|netscan(?:\.exe)?|nxc(?:\.exe)?|w(?:\.exe)?)\b',
        re.IGNORECASE
    )
    for match in cmd_regex.finditer(clean_text):
        val = match.group(0).strip().lower()
        if val not in commands:
            commands.append(val)
            
    # Mots clés typiques pour identifier les groupes d'attaquants (actors)
    actor_keywords = ["spider", "gang", "group", "actor", "team", "ransomware", "threat", "unc", "apt", "lynx", "lockbit", "ransomhub", "interlock", "lunar"]

    # Patterns de bruit a exclure de toutes les sections NLP
    _CVE_PAT    = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)
    _HASH_PAT   = re.compile(r'^[a-fA-F0-9]{32,64}$')
    _HTML_NOISE = re.compile(r'&(?:nbsp|amp|quot|lt|gt|#\d+);')
    _SIGMA_UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', re.I)

    for ent in doc.ents:
        val = ent.text.strip().replace('"', '').replace("'", "")
        if len(val) <= 2 or val.isdigit():
            continue
        if any(c in val for c in ('\\', '*', '<', '>', '{', '}', '[', ']', '=')):
            continue
        # Exclure CVEs — section dediee
        if _CVE_PAT.match(val.strip()):
            continue
        # Exclure hashes bruts
        if _HASH_PAT.match(val.strip()):
            continue
        # Nettoyer les residus HTML
        if _HTML_NOISE.search(val):
            val = _HTML_NOISE.sub(' ', val).strip()
            if len(val) <= 2:
                continue
        # Exclure UUIDs Sigma rules
        if _SIGMA_UUID.search(val):
            continue
        # Exclure tokens type "EID 1", "T1059"
        if re.match(r'^[A-Z]{1,4}\s*\d+$', val.strip()):
            continue

        val_lower = val.lower()

        # A. Commandes et executables
        if val_lower.endswith(('.exe', '.dll', '.bat', '.ps1', '.sh', '.bin')) or val_lower in ["powershell", "cmd", "wmi", "wmic", "netexec", "anydesk"]:
            if val not in commands:
                commands.append(val)
        # B. Groupes d'attaquants (Actor)
        elif ent.label_ == "ORG" and any(k in val_lower for k in actor_keywords):
            if val not in actors:
                actors.append(val)
        # C. Victimes / Infra ciblee
        elif ent.label_ in ("GPE", "LOC", "ORG"):
            if ent.label_ in ("GPE", "LOC"):
                if val not in victims:
                    victims.append(val)
            else:
                if val not in victims and val not in actors:
                    victims.append(val)
        # D. PRODUCT spaCy -> section technology
        elif ent.label_ == "PRODUCT":
            clean_prod = val.strip()
            if clean_prod not in technologies and not _TAG_NOISE.search(clean_prod) and '\n' not in clean_prod:
                technologies.append(clean_prod)
        # E. Autres entites contextuelles
        else:
            if val not in others and val not in actors and val not in victims and val not in commands:
                others.append(val)
                
    return {
        "actor": sorted(set(actors)),
        "victim": sorted(set(victims)),
        "command": sorted(set(commands)),
        "technology": sorted(set(technologies)),
        "other": sorted(set(others))
    }

SOURCE_NAME   = "DFIR Report"
BASE_DIR      = os.path.dirname(EXTRACTORS_DIR)
SOURCE_DIR = os.path.join(BASE_DIR, "global_output", "sources", "The DFIR Report", "collection")
INPUT_FILE    = os.path.join(SOURCE_DIR, "dfir_report_data.json")

# Extensions de fichier supplémentaires à rejeter comme domaines (faux positifs blog)
BLOG_INVALID_EXTENSIONS = {
    '.cmd', '.ini', '.cfg', '.txt', '.name', '.log', '.xml', '.json',
    '.yaml', '.ps1', '.reg', '.db', '.pdb', '.sys', '.conf', '.config',
    '.lic', '.msc', '.lnk', '.php', '.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.html', '.htm'
}

# Domaines/URLs internes du blog ou légitimes à ignorer
BLOG_WHITELIST = {
    "thedfirreport.com",
    "nodejs.org",
    "microsoft.com",
    "google.com",
    "github.com",
    "githubusercontent.com",
    "filebase.com",
    "amazonaws.com",
    "dropbox.com",
    "windows.net",
    "office.com",
    # Réseaux sociaux / boutons de partage WordPress
    "x.com",
    "twitter.com",
    "reddit.com",
    "linkedin.com",
    "whatsapp.com",
    "facebook.com",
    # Namespace W3C / SVG embarqué dans le HTML
    "w3.org",
    # Sites de vendors sécurité cités comme références dans les articles
    "atos.net",
    "sysdig.com",
    "expel.com",
    "softperfect.com",
    "virustotal.com",
    "any.run",
    "hybrid-analysis.com",
    "bazaar.abuse.ch",
    "urlhaus.abuse.ch",
    "threatfox.abuse.ch",
    # Références encyclopédiques et médias
    "youtube.com",
    "youtu.be",
    "medium.com",
    "wikipedia.org",
    "wikimedia.org",
    "substack.com",
    # Domaines CTI sources de données / références externes
    "group-ib.com",
    "intrinsec.com",
    "reliaquest.com",
    "nextron-systems.com",
    "fidelissecurity.com",
    "bitsight.com",
    "swisscom.ch",
    "cyjax.com",
    "secureworks.com",
    "sigmasearchengine.com",
    "detection.fyi",
    "advanced-ip-scanner.com",
    "temp.sh",
    "secureserver.net",
    "abuse.ch"
}

# Motifs de namespace .NET ou technologie (pas des IOC)
TECH_NAMESPACE_PATTERN = re.compile(
    r'^(system\.|microsoft\.|windows\.|net\.|com\.|org\.|java\.|sun\.)',
    re.IGNORECASE
)

# Les articles avec IOCs → dfir_report_extracted.json
# Les articles avec uniquement CVEs (sans IOCs) → dfir_report_vuln_extracted.json
OUTPUT_DIR = os.path.join(BASE_DIR, "global_output", "sources", "The DFIR Report", "extraction")
IOC_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dfir_report_extracted.json")
VULN_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dfir_report_vuln_extracted.json")

TRACKING_DIR  = os.path.join(EXTRACTORS_DIR, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "dfir_report_tracking.json")


def _get_mongo_tracker():
    import sys
    import os
    project_root = os.path.abspath(os.path.join(EXTRACTORS_DIR, ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    try:
        from utils.tracking import ExtractionTracker
        return ExtractionTracker(SOURCE_NAME)
    except Exception as e:
        print(f"Failed to load Tracker: {e}")
        return None

def _load_tracking():
    oldest = None
    recent = None
    tracker = _get_mongo_tracker()
    if tracker:
        data = tracker.get_tracking()
        oldest = data.get("oldest_extracted_at")
        recent = data.get("recent_extracted_at")
        # migration fallback
        if not recent and data.get("last_extracted_at"):
            recent = data.get("last_extracted_at")
            oldest = data.get("last_extracted_at")
    return oldest, recent


def _save_tracking(oldest, recent):
    tracker = _get_mongo_tracker()
    if tracker:
        tracker.save_tracking({
            "oldest_extracted_at": oldest,
            "recent_extracted_at": recent
        })


def _load_existing(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_json(path: str, data: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _is_false_positive(ioc: dict, nlp_analysis: dict = None) -> bool:
    """Détecte les faux positifs spécifiques aux articles de blog en utilisant le contexte NLP."""
    val  = ioc.get("value", "")
    typ  = ioc.get("type", "")

    if typ == "ip":
        # IPv6 vide ou non-routable
        if val in ("::", "0.0.0.0"):
            return True
        try:
            addr = ipaddress.ip_address(val)
            if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_private or addr.is_multicast or addr.is_reserved:
                return True
            # Résolveurs DNS publics du contexte
            DNS_RESOLVERS = {
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", 
                "208.67.222.222", "208.67.220.220"
            }
            if val in DNS_RESOLVERS:
                return True
            # Numéros de version déguisés en IP (ex: 7.2.9.0, 18.20.5, 19.0.0.0)
            # Heuristique : dernier octet = 0 ET premier octet <= 20 (version basse plausible)
            parts = val.split(".")
            if len(parts) == 4 and parts[-1] == "0":
                return True
        except ValueError:
            return True

    # Récupérer les noms légitimes depuis le contexte NLP
    legit_names = set()
    if nlp_analysis:
        for key in ["victim", "command", "other"]:
            for item in nlp_analysis.get(key, []):
                cleaned_item = re.sub(r'[^a-z0-9]', '', item.lower())
                if len(cleaned_item) > 2:
                    legit_names.add(cleaned_item)

    def _get_sld(domain):
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return domain.lower()
        if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "edu"):
            return parts[-3]
        return parts[-2]

    if typ == "domaine":
        val_lower = val.lower()
        # Propriétés techniques Elementor/WordPress
        if val_lower.startswith(("state.", "callbacks.", "actions.")):
            return True
        # Extension de fichier (pas un domaine)
        for ext in BLOG_INVALID_EXTENSIONS:
            if val_lower.endswith(ext):
                return True
        # Namespace technologique (.NET, Java, etc.)
        if TECH_NAMESPACE_PATTERN.match(val_lower):
            return True
        # Whitelist blog/légitimes (domaine exact ou sous-domaine)
        for w in BLOG_WHITELIST:
            if val_lower == w or val_lower.endswith("." + w):
                return True
        # Pas de point = pas un domaine valide
        if "." not in val_lower:
            return True

        # Vérification TLD : un TLD > 6 chars qui n'est pas connu → très probablement pas un vrai domaine
        # Ex: "s3.filebase" → TLD="filebase" (8 chars) → faux positif
        _KNOWN_LONG_TLDS = {"museum", "travel", "mobi", "arpa", "local"}
        tld_candidate = val_lower.rsplit(".", 1)[-1]
        if len(tld_candidate) > 6 and tld_candidate not in _KNOWN_LONG_TLDS:
            return True

        # Filtre dynamique basé sur le contexte NLP
        sld = _get_sld(val_lower)
        cleaned_sld = re.sub(r'[^a-z0-9]', '', sld)
        if cleaned_sld in legit_names:
            return True

    if typ == "url":
        val_lower = val.lower()
        # Filtre toutes les URLs dont l'hôte est dans la whitelist ou correspond aux noms NLP légitimes
        try:
            from urllib.parse import urlparse
            host = urlparse(val_lower).netloc.split(":")[0]
            for w in BLOG_WHITELIST:
                if host == w or host.endswith("." + w):
                    return True
            
            # Filtre dynamique basé sur le contexte NLP
            sld = _get_sld(host)
            cleaned_sld = re.sub(r'[^a-z0-9]', '', sld)
            if cleaned_sld in legit_names:
                return True
        except Exception:
            pass

    return False


def _build_threat_summary(article: dict, iocs: list, cves: list, tags: list) -> str:
    """Construit un résumé du threat basé sur le contexte de l'article."""
    title = article.get("title", "Unknown Threat")

    # Types d'IOC présents
    ioc_types = {}
    for ioc in iocs:
        t = ioc.get("type", "unknown")
        ioc_types[t] = ioc_types.get(t, 0) + 1

    ioc_breakdown = ", ".join(
        f"{count} {typ}" for typ, count in sorted(ioc_types.items())
    )

    # CVEs
    cve_ids = [c.get("id", "") for c in cves if c.get("id")]
    cve_str = f" | CVEs: {', '.join(cve_ids)}" if cve_ids else ""

    # Tags threat (malware, ransomware, etc.)
    threat_tags = [t for t in tags if t not in ("flash alert", "dfir report")]
    tag_str = f" | Tags: {', '.join(threat_tags[:5])}" if threat_tags else ""

    return (
        f"[THREAT] {title} | "
        f"IOCs: {len(iocs)} ({ioc_breakdown})"
        f"{cve_str}"
        f"{tag_str}"
    )


def _make_ioc_record(article: dict, iocs: list, cves: list, tags: list, nlp_analysis: dict = None) -> dict:
    """Format pour __TEMP__/global_output/output_cve_ioc — sera traité par l'enrichissement IOC normal.
    Pas d'ioc_enrichment ici : c'est le rôle de l'étape enrichissement."""
    record = {
        "source":     SOURCE_NAME,
        "record_id":  article["id"],
        "summary":    _build_threat_summary(article, iocs, cves, tags),
        "iocs":       iocs,
        "cves":       cves,
        "tags":       tags,
        "references": [article.get("link", "")],
        "attributes": {},
        "collected_at": article.get("published") or article.get("collected_at"),
        "description": article.get("title", ""),
    }
    if nlp_analysis:
        record["attributes"]["nlp_analysis"] = nlp_analysis
    return record


def _make_vuln_record(article: dict, cves: list, tags: list, nlp_analysis: dict = None) -> dict:
    """
    Format pour __TEMP__/global_output/output_enrichment — bypass enrichissement IOC.
    Aucun IOC, uniquement CVE + contexte article.
    La corrélation le lira directement depuis __TEMP__/global_output/output_enrichment/.
    """
    now = datetime.now(timezone.utc).isoformat()
    title = article.get("title", "Unknown Vulnerability Threat")
    cve_ids = [c.get("id", "") for c in cves if c.get("id")]
    record = {
        "source":     SOURCE_NAME,
        "record_id":  article["id"],
        "summary":    f"[VULNERABILITY] {title} | CVEs: {', '.join(cve_ids)} | No IOC found. Sent directly to correlation.",
        "iocs":       [],
        "cves":       cves,
        "tags":       tags,
        "references": [article.get("link", "")],
        "attributes": {
            "classification": "VULNERABILITY",
            "tlp":            "TLP:CLEAR",
            "enriched_at":    now,
        },
        "collected_at": article.get("published") or article.get("collected_at"),
        "description":  article.get("rss_excerpt") or article.get("title", ""),
    }
    if nlp_analysis:
        record["attributes"]["nlp_analysis"] = nlp_analysis
    return record


def _get_item_timestamp(article):
    date_fields = [
        'collected_at', 'submission_time', 'extracted_at', 'created_at', 
        'created', 'reportedAt', 'lastReportedAt', 'dateAdded', 
        'date', 'published', 'modified', 'last_modified'
    ]
    for df in date_fields:
        if article.get(df):
            return article.get(df)
    return None


def run_extraction():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(INPUT_FILE):
        print(f"[{SOURCE_NAME}] Fichier introuvable : {INPUT_FILE}")
        return

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            articles = json.load(f)
    except Exception as e:
        print(f"[{SOURCE_NAME}] Erreur lecture : {e}")
        return

    if not isinstance(articles, list):
        articles = [articles]

    oldest_extracted_at, recent_extracted_at = _load_tracking()
    force_full    = "--full" in sys.argv
    if force_full:
        oldest_extracted_at = None
        recent_extracted_at = None
        print(f"[{SOURCE_NAME}] Mode FORCE FULL - retraitement de tous les articles.")

    extractor = BaseExtractor()
    new_articles = extractor.filter_by_timestamp(articles, oldest_extracted_at, recent_extracted_at)
    if not new_articles:
        print(f"[{SOURCE_NAME}] Aucun nouvel article à traiter.")
        return

    print(f"[{SOURCE_NAME}] {len(new_articles)} nouvel(s) article(s) sur {len(articles)} total.")

    ioc_records  = []
    vuln_records = []

    current_oldest = oldest_extracted_at
    current_recent = recent_extracted_at

    for article in new_articles:
        # Texte combiné : contenu complet + section IOC si différente
        text = (article.get("content") or "") + "\n" + (article.get("ioc_section") or "")

        # 1. NLP Context Extraction
        nlp_analysis = _extract_nlp_context(text)

        extracted = extractor.extract_from_text(text)
        iocs = extracted.get("iocs", [])
        cves = extracted.get("cves", [])

        # Construire les tags depuis les champs article
        raw_tags = article.get("tags", [])
        tags = [t.lower().strip() for t in raw_tags if isinstance(t, str)]

        # Filtrer les faux positifs et annoter chaque IOC avec la source
        clean_iocs = []
        for ioc in iocs:
            ioc["source"] = SOURCE_NAME
            if _is_false_positive(ioc, nlp_analysis):
                continue
            clean_iocs.append(ioc)
        iocs = clean_iocs

        # Ajouter le nom du fichier comme tag
        for ioc in iocs:
            f = ioc.get("file")
            if f:
                f_tag = f"file:{f.lower().strip()}"
                if f_tag not in tags:
                    tags.append(f_tag)

        # Ajouter les technologies identifiees par NLP comme tags (produits, versions, logiciels)
        _TAG_NOISE_PAT = re.compile(
            r'share\s+on|linkedin|facebook|whatsapp|twitter|subscribe|newsletter|'
            r'annually|monthly|weekly|^\d+$',
            re.IGNORECASE
        )
        if nlp_analysis:
            for tech in nlp_analysis.get("technology", []):
                # Uniquement les entrees propres : pas de saut de ligne, longueur raisonnable
                if not tech or '\n' in tech or len(tech) > 60:
                    continue
                if _TAG_NOISE_PAT.search(tech):
                    continue
                tech_tag = f"tech:{tech.lower().strip()}"
                if tech_tag not in tags:
                    tags.append(tech_tag)

        # Annoter chaque CVE avec la source
        for cve in cves:
            cve["source"] = SOURCE_NAME

        has_ioc  = len(iocs) > 0
        has_cve  = len(cves) > 0

        if has_ioc:
            # Cas 1 : IOC présents → pipeline enrichissement IOC normal
            record = _make_ioc_record(article, iocs, cves, tags, nlp_analysis)
            ioc_records.append(record)
            print(f"  [IOC]  {article.get('title','?')[:60]} — {len(iocs)} IOCs, {len(cves)} CVEs")

        elif has_cve:
            # Cas 2 : CVE seulement, pas d'IOC → bypass enrichissement, direct correlation
            record = _make_vuln_record(article, cves, tags, nlp_analysis)
            vuln_records.append(record)
            print(f"  [VULN] {article.get('title','?')[:60]} — {len(cves)} CVEs (no IOC)")

        else:
            # Cas 3 : Ni IOC ni CVE → skip
            print(f"  [SKIP] {article.get('title','?')[:60]} — rien à extraire")

        # Update bounds using published or collected_at
        item_ts = _get_item_timestamp(article)
        if item_ts:
            if not current_oldest or item_ts < current_oldest:
                current_oldest = item_ts
            if not current_recent or item_ts > current_recent:
                current_recent = item_ts

    # Sauvegarde : split des records (IOC vs VULN) en deux fichiers distincts
    if force_full:
        merged_ioc = ioc_records
    else:
        existing_ioc = _load_existing(IOC_OUTPUT_FILE)
        existing_ioc_ids = {r["record_id"] for r in existing_ioc if "record_id" in r}
        merged_ioc = existing_ioc + [r for r in ioc_records if r.get("record_id") not in existing_ioc_ids]
    _save_json(IOC_OUTPUT_FILE, merged_ioc)
    print(f"[{SOURCE_NAME}] {len(ioc_records)} IOC -> {IOC_OUTPUT_FILE}")

    if force_full:
        merged_vuln = vuln_records
    else:
        existing_vuln = _load_existing(VULN_OUTPUT_FILE)
        existing_vuln_ids = {r["record_id"] for r in existing_vuln if "record_id" in r}
        merged_vuln = existing_vuln + [r for r in vuln_records if r.get("record_id") not in existing_vuln_ids]
    _save_json(VULN_OUTPUT_FILE, merged_vuln)
    print(f"[{SOURCE_NAME}] {len(vuln_records)} VULN -> {VULN_OUTPUT_FILE}")

    _save_tracking(current_oldest, current_recent)
    print(f"[{SOURCE_NAME}] Extraction terminée.")


if __name__ == "__main__":
    run_extraction()
