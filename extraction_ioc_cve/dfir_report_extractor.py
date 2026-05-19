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

SOURCE_NAME   = "DFIR Report"
BASE_DIR      = os.path.dirname(EXTRACTORS_DIR)
SOURCE_DIR    = os.path.join(BASE_DIR, "Sources_data", "The DFIR Report")
INPUT_FILE    = os.path.join(SOURCE_DIR, "dfir_report_data.json")

# Extensions de fichier supplémentaires à rejeter comme domaines (faux positifs blog)
BLOG_INVALID_EXTENSIONS = {
    '.cmd', '.ini', '.cfg', '.txt', '.name', '.log', '.xml', '.json',
    '.yaml', '.ps1', '.reg', '.db', '.pdb', '.sys',
}

# Domaines/URLs internes du blog ou légitimes à ignorer
BLOG_WHITELIST = {
    "thedfirreport.com",
    "nodejs.org",
    "microsoft.com",
    "google.com",
    "github.com",
}

# Motifs de namespace .NET ou technologie (pas des IOC)
TECH_NAMESPACE_PATTERN = re.compile(
    r'^(system\.|microsoft\.|windows\.|net\.|com\.|org\.|java\.|sun\.)',
    re.IGNORECASE
)

# Articles avec IOC  → pipeline enrichissement normal
IOC_OUTPUT_DIR  = os.path.join(BASE_DIR, "output_cve_ioc")
IOC_OUTPUT_FILE = os.path.join(IOC_OUTPUT_DIR, "dfir_report_extracted.json")

# Articles CVE-only  → directement en sortie enrichissement (bypass enrichissement IOC)
VULN_OUTPUT_DIR  = os.path.join(BASE_DIR, "output_enrichment")
VULN_OUTPUT_FILE = os.path.join(VULN_OUTPUT_DIR, "dfir_report_vuln_enriched.json")

TRACKING_DIR  = os.path.join(EXTRACTORS_DIR, "tracking")
TRACKING_FILE = os.path.join(TRACKING_DIR, "dfir_report_tracking.json")


def _load_tracking():
    if not os.path.exists(TRACKING_FILE):
        return set()
    try:
        with open(TRACKING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        processed = data.get("processed_ids", [])
        return set(processed)
    except Exception:
        return set()


def _save_tracking(processed_ids: set):
    os.makedirs(TRACKING_DIR, exist_ok=True)
    with open(TRACKING_FILE, "w", encoding="utf-8") as f:
        json.dump({"processed_ids": sorted(processed_ids)}, f, indent=2)


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


def _is_false_positive(ioc: dict) -> bool:
    """Détecte les faux positifs spécifiques aux articles de blog."""
    val  = ioc.get("value", "")
    typ  = ioc.get("type", "")

    if typ == "ip":
        # IPv6 vide ou non-routable
        if val in ("::", "0.0.0.0"):
            return True
        try:
            addr = ipaddress.ip_address(val)
            if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
                return True
            # Numéros de version déguisés en IP (ex: 7.2.9.0, 18.20.5, 19.0.0.0)
            # Heuristique : dernier octet = 0 ET premier octet <= 20 (version basse plausible)
            parts = val.split(".")
            if len(parts) == 4 and parts[-1] == "0":
                return True
        except ValueError:
            return True

    if typ == "domaine":
        val_lower = val.lower()
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

    if typ == "url":
        val_lower = val.lower()
        # Filtre toutes les URLs dont l'hôte est dans la whitelist
        try:
            from urllib.parse import urlparse
            host = urlparse(val_lower).netloc.split(":")[0]
            for w in BLOG_WHITELIST:
                if host == w or host.endswith("." + w):
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


def _make_ioc_record(article: dict, iocs: list, cves: list, tags: list) -> dict:
    """Format pour output_cve_ioc — sera traité par l'enrichissement IOC normal.
    Pas d'ioc_enrichment ici : c'est le rôle de l'étape enrichissement."""
    return {
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


def _make_vuln_record(article: dict, cves: list, tags: list) -> dict:
    """
    Format pour output_enrichment — bypass enrichissement IOC.
    Aucun IOC, uniquement CVE + contexte article.
    La corrélation le lira directement depuis output_enrichment/.
    """
    now = datetime.now(timezone.utc).isoformat()
    enriched_cves = []
    for cve in cves:
        cve_id = cve.get("id", "")
        enriched_cves.append({
            "id":     cve_id,
            "source": SOURCE_NAME,
            "ioc_enrichment": {
                "classification": "VULNERABILITY",
                "tlp":            "TLP:CLEAR",
                "enriched_at":    now,
            }
        })

    return {
        "source":     SOURCE_NAME,
        "record_id":  article["id"],
        "summary":    f"[VULNERABILITY] {len(cves)} CVE(s) extracted — no IOC found. Sent directly to correlation.",
        "iocs":       [],
        "cves":       enriched_cves,
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


def run_extraction():
    os.makedirs(IOC_OUTPUT_DIR, exist_ok=True)
    os.makedirs(VULN_OUTPUT_DIR, exist_ok=True)

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

    processed_ids = _load_tracking()
    force_full    = "--full" in sys.argv
    if force_full:
        processed_ids = set()
        print(f"[{SOURCE_NAME}] Mode FORCE FULL - retraitement de tous les articles.")

    new_articles = [a for a in articles if a.get("id") not in processed_ids]
    if not new_articles:
        print(f"[{SOURCE_NAME}] Aucun nouvel article à traiter.")
        return

    print(f"[{SOURCE_NAME}] {len(new_articles)} nouvel(s) article(s) sur {len(articles)} total.")

    extractor   = BaseExtractor()
    ioc_records  = []
    vuln_records = []

    for article in new_articles:
        # Texte combiné : contenu complet + section IOC si différente
        text = (article.get("content") or "") + "\n" + (article.get("ioc_section") or "")

        extracted = extractor.extract_from_text(text)
        iocs = extracted.get("iocs", [])
        cves = extracted.get("cves", [])

        # Construire les tags depuis les champs article
        raw_tags = article.get("tags", [])
        tags = [t.lower().strip() for t in raw_tags if isinstance(t, str)]

        # Filtrer les faux positifs et annoter chaque IOC avec la source
        # Pas d'ioc_enrichment ici — c'est l'étape enrichissement qui l'ajoute
        clean_iocs = []
        for ioc in iocs:
            ioc["source"] = SOURCE_NAME
            if _is_false_positive(ioc):
                continue
            clean_iocs.append(ioc)
        iocs = clean_iocs

        # Annoter chaque CVE avec la source
        for cve in cves:
            cve["source"] = SOURCE_NAME

        has_ioc  = len(iocs) > 0
        has_cve  = len(cves) > 0

        if has_ioc:
            # Cas 1 : IOC présents → pipeline enrichissement IOC normal
            record = _make_ioc_record(article, iocs, cves, tags)
            ioc_records.append(record)
            print(f"  [IOC]  {article.get('title','?')[:60]} — {len(iocs)} IOCs, {len(cves)} CVEs")

        elif has_cve:
            # Cas 2 : CVE seulement, pas d'IOC → bypass enrichissement, direct correlation
            record = _make_vuln_record(article, cves, tags)
            vuln_records.append(record)
            print(f"  [VULN] {article.get('title','?')[:60]} — {len(cves)} CVEs (no IOC)")

        else:
            # Cas 3 : Ni IOC ni CVE → skip
            print(f"  [SKIP] {article.get('title','?')[:60]} — rien à extraire")

        processed_ids.add(article["id"])

    # Sauvegarde : en mode --full on écrase, sinon on merge (ajout uniquement)
    if ioc_records:
        if force_full:
            merged_ioc = ioc_records
        else:
            existing_ioc = _load_existing(IOC_OUTPUT_FILE)
            existing_ids = {r["record_id"] for r in existing_ioc}
            merged_ioc   = existing_ioc + [r for r in ioc_records if r["record_id"] not in existing_ids]
        _save_json(IOC_OUTPUT_FILE, merged_ioc)
        print(f"[{SOURCE_NAME}] {len(ioc_records)} article(s) IOC -> {IOC_OUTPUT_FILE}")

        # Copie aussi vers output_enrichment/ pour que VT/URLscan/AbuseIPDB les traitent.
        # --full : remplace entièrement les records (IOCs filtrés recalculés)
        # Normal : ajoute seulement les nouveaux articles
        enriched_file = os.path.join(VULN_OUTPUT_DIR, "dfir_report_enriched.json")
        if force_full:
            _save_json(enriched_file, ioc_records)
            print(f"[{SOURCE_NAME}] {len(ioc_records)} article(s) IOC -> output_enrichment/dfir_report_enriched.json (FULL)")
        else:
            existing_enriched = _load_existing(enriched_file)
            enriched_ids = {r["record_id"] for r in existing_enriched}
            new_for_enrichment = [r for r in ioc_records if r["record_id"] not in enriched_ids]
            if new_for_enrichment:
                merged_enriched = existing_enriched + new_for_enrichment
                _save_json(enriched_file, merged_enriched)
                print(f"[{SOURCE_NAME}] {len(new_for_enrichment)} article(s) IOC -> output_enrichment/dfir_report_enriched.json")

    if vuln_records:
        if force_full:
            merged_vuln = vuln_records
        else:
            existing_vuln = _load_existing(VULN_OUTPUT_FILE)
            existing_ids  = {r["record_id"] for r in existing_vuln}
            merged_vuln   = existing_vuln + [r for r in vuln_records if r["record_id"] not in existing_ids]
        _save_json(VULN_OUTPUT_FILE, merged_vuln)
        print(f"[{SOURCE_NAME}] {len(vuln_records)} article(s) CVE-only -> {VULN_OUTPUT_FILE}")

    _save_tracking(processed_ids)
    print(f"[{SOURCE_NAME}] Extraction terminée.")


if __name__ == "__main__":
    run_extraction()
