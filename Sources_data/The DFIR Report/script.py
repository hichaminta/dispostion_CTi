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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("DFIR-Collector")


# ─────────────────────────────────────────────
# Tracking
# ─────────────────────────────────────────────

def load_tracking() -> dict:
    if os.path.exists(TRACKING):
        try:
            with open(TRACKING, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"collected_ids": []}


def save_tracking(data: dict):
    with open(TRACKING, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


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

def run():
    log.info("=== DFIR Report Collector ===")
    tracking   = load_tracking()
    seen_ids   = set(tracking.get("collected_ids", []))
    existing   = load_existing()
    existing_map = {r["id"]: r for r in existing}

    articles = fetch_rss()
    if not articles:
        log.warning("Aucun article récupéré depuis le flux RSS.")
        return

    new_count = 0
    for art in articles[:MAX_ARTICLES]:
        if art["id"] in seen_ids:
            log.info(f"  [SKIP] Déjà collecté : {art['title'][:60]}")
            continue

        existing_map[art["id"]] = art
        seen_ids.add(art["id"])
        new_count += 1
        log.info(f"  [NEW]  {art['title'][:60]}")

    if new_count > 0:
        records = list(existing_map.values())
        save_data(records)
        tracking["collected_ids"] = sorted(seen_ids)
        save_tracking(tracking)
        log.info(f"Sauvegarde : {len(records)} articles total, {new_count} nouveaux.")
    else:
        log.info("Aucun nouvel article.")

    log.info("=== Collecte terminée ===")


if __name__ == "__main__":
    run()
