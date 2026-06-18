import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import logging
import requests
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "dfir_report_data.json")
TRACKING    = os.path.join(SCRIPT_DIR, "tracking.json")

RSS_URL     = "https://thedfirreport.com/feed/"
MAX_ARTICLES = 20   # articles maximum par run

logging.basicConfig(encoding="utf-8", level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("DFIR-Collector")


# ─────────────────────────────────────────────
# Tracking
# ─────────────────────────────────────────────

def _get_mongo_tracker():
    import sys
    import os
    # Ensure utils is in path dynamically
    project_root = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    try:
        from utils.mongo_tracking import SourceTracker
        source_name = os.path.basename(SCRIPT_DIR)
        return SourceTracker(source_name)
    except Exception as e:
        logging.error(f"Failed to load MongoTracker: {e}")
        return None

def load_tracking() -> dict:
    tracker = _get_mongo_tracker()
    if tracker:
        doc = tracker.get_tracking()
        if doc:
            return doc
    return {
        "earliest_modified": None,
        "latest_modified": None,
        "last_sync_success": None,
        "last_sync_attempt": None,
        "last_run": None
    }


def save_tracking(data: dict):
    tracker = _get_mongo_tracker()
    if tracker:
        tracker.save_tracking(data)


# ─────────────────────────────────────────────
# Chargement / Sauvegarde JSON
# ─────────────────────────────────────────────

def load_existing() -> list:
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_data(records: list):
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    # Snapshot journalier
    today = datetime.now().strftime("%Y-%m-%d")
    daily = os.path.join(SCRIPT_DIR, f"dfir_report_data_{today}.json")
    with open(daily, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────
# Parsing RSS
# ─────────────────────────────────────────────

NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc":      "http://purl.org/dc/elements/1.1/",
    "atom":    "http://www.w3.org/2005/Atom",
}


def fetch_rss() -> list:
    """Télécharge et parse le flux RSS DFIR Report."""
    try:
        resp = requests.get(RSS_URL, timeout=30, headers={"User-Agent": "CTI-Platform/1.0"})
        resp.raise_for_status()
    except Exception as e:
        log.error(f"Erreur fetch RSS : {e}")
        return []

    try:
        root = ElementTree.fromstring(resp.content)
    except Exception as e:
        log.error(f"Erreur parsing RSS XML : {e}")
        return []

    items = root.findall(".//item")
    articles = []
    for item in items:
        def txt(tag, ns=None):
            el = item.find(tag) if ns is None else item.find(tag, ns)
            return el.text.strip() if el is not None and el.text else ""

        # Catégories / tags
        tags = [c.text.strip() for c in item.findall("category") if c.text]

        # Contenu complet (balise content:encoded ou description)
        content = txt("content:encoded", NS) or txt("description")

        # Texte brut pour la description RSS
        rss_excerpt = txt("description")[:500] if txt("description") else ""

        art = {
            "id":          txt("guid") or txt("link"),
            "title":       txt("title"),
            "link":        txt("link"),
            "published":   _parse_date(txt("pubDate")),
            "rss_excerpt": rss_excerpt,
            "tags":        tags,
            "content":     content,
            "ioc_section": _extract_ioc_section(content),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
        if art["id"]:
            articles.append(art)

    log.info(f"RSS : {len(articles)} article(s) trouvé(s)")
    return articles


def _parse_date(date_str: str) -> str:
    """Convertit la date RSS en ISO 8601."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(date_str).isoformat()
    except Exception:
        return date_str


def _extract_ioc_section(html_content: str) -> str:
    """
    Extrait la section IOC du contenu HTML de l'article.
    Le DFIR Report met généralement les IOCs sous un titre 'Indicators',
    'IOCs', 'Indicators of Compromise' ou similaire.
    """
    if not html_content:
        return ""

    # Chercher un marqueur de section IOC dans le HTML/texte brut
    import re
    markers = [
        r"Indicators of Compromise",
        r"Indicators",
        r"IOCs?",
        r"Indicators \(IOC\)",
    ]
    pattern = "|".join(markers)

    # Chercher la position du marqueur
    match = re.search(pattern, html_content, re.IGNORECASE)
    if match:
        # Retourner tout le contenu à partir du marqueur IOC
        return html_content[match.start():]

    # Si pas de section IOC distincte, retourner le contenu complet
    # (l'extracteur fera le tri avec BaseExtractor)
    return html_content


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def fetch_full_article_content(url: str) -> str:
    """Télécharge l'article complet et extrait le bloc entry-content."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        html = resp.text
        
        # Trouver la div entry-content
        import re
        start_match = re.search(r'<div[^>]*class=["\'][^"\']*entry-content[^"\']*["\'][^>]*>', html)
        if start_match:
            start_idx = start_match.end()
            chunk = html[start_idx:start_idx+150000]
            depth = 1
            pos = 0
            while depth > 0 and pos < len(chunk):
                next_div = chunk.find("<div", pos)
                next_close = chunk.find("</div", pos)
                if next_close == -1:
                    break
                if next_div != -1 and next_div < next_close:
                    depth += 1
                    pos = next_div + 4
                else:
                    depth -= 1
                    pos = next_close + 5
            
            entry_html = chunk[:pos] if pos > 0 else chunk
            return entry_html
    except Exception as e:
        log.error(f"Erreur téléchargement article complet ({url}) : {e}")
    return ""


def run():
    log.info("=== DFIR Report Collector ===")
    tracking   = load_tracking()
    # Remove collected_ids if present from old tracking to clean up
    tracking.pop("collected_ids", None)

    existing   = load_existing()
    existing_map = {r["id"]: r for r in existing}
    seen_ids   = set(existing_map.keys())

    now_iso = datetime.now(timezone.utc).isoformat()
    tracking["last_sync_attempt"] = now_iso
    tracking["last_run"] = now_iso

    articles = fetch_rss()
    if not articles:
        log.warning("Aucun article récupéré depuis le flux RSS.")
        save_tracking(tracking)
        return

    new_count = 0
    updated_count = 0
    for art in articles[:MAX_ARTICLES]:
        is_already_collected = art["id"] in seen_ids
        existing_art = existing_map.get(art["id"]) if is_already_collected else None
        
        # Check if we need to fetch/update the full content
        needs_full_content = (
            not existing_art 
            or not existing_art.get("content") 
            or len(existing_art.get("content", "")) < 1000
        )

        if is_already_collected and not needs_full_content:
            log.info(f"  [SKIP] Déjà collecté : {art['title'][:60]}")
            continue

        # Fetch the full HTML page content to extract real IOCs
        log.info(f"  [FETCH] Téléchargement de l'article complet : {art['title'][:60]}")
        full_content = fetch_full_article_content(art["link"])
        if full_content:
            art["content"] = full_content
            art["ioc_section"] = _extract_ioc_section(full_content)

        existing_map[art["id"]] = art
        seen_ids.add(art["id"])
        
        if is_already_collected:
            updated_count += 1
            log.info(f"  [UPDATE] {art['title'][:60]}")
        else:
            new_count += 1
            log.info(f"  [NEW]  {art['title'][:60]}")

    # Calculate min/max published dates
    all_published_dates = [r.get("published") for r in existing_map.values() if r.get("published")]
    if all_published_dates:
        tracking["earliest_modified"] = min(all_published_dates)
        tracking["latest_modified"] = max(all_published_dates)

    tracking["last_sync_success"] = now_iso

    if new_count > 0 or updated_count > 0:
        records = list(existing_map.values())
        save_data(records)
        save_tracking(tracking)
        log.info(f"Sauvegarde : {len(records)} articles total, {new_count} nouveaux, {updated_count} mis à jour.")
    else:
        save_tracking(tracking)
        log.info("Aucun nouvel article ou mise à jour.")

    log.info("=== Collecte terminée ===")


if __name__ == "__main__":
    run()
