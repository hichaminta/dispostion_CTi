import os
import json
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any

import requests
import csv

# ============================================================
# Configuration
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_JSON = os.path.join(SCRIPT_DIR, "spamhaus_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "tracking.json")
OLD_TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

SPAMHAUS_FEEDS = {
    "drop": "https://www.spamhaus.org/drop/drop.txt",
    "edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "dropv6": "https://www.spamhaus.org/drop/dropv6.txt",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CTI-Collector/1.0; +https://example.local)"
}

TIMEOUT = 30


# ============================================================
# Utils
# ============================================================
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_tracking():
    """Charge le tracking JSON ou migre depuis l'ancien CSV."""
    if os.path.exists(TRACKING_FILE):
        try:
            with open(TRACKING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    
    # Migration depuis l'ancien CSV
    if os.path.exists(OLD_TRACKING_FILE):
        try:
            with open(OLD_TRACKING_FILE, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                rows = list(reader)
                if rows:
                    return {"latest_modified": rows[-1][0]}
        except:
            pass
    return {}

def save_tracking_atomic(tracking: dict):
    """Sauvegarde le tracking JSON de manière atomique."""
    tmp_file = TRACKING_FILE + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(tracking, f, indent=4, ensure_ascii=False)
        os.replace(tmp_file, TRACKING_FILE)
    except Exception as e:
        print(f"Erreur tracking : {e}")

def save_json_atomic(path: str, data: Any) -> None:
    """Sauvegarde les données JSON de manière atomique."""
    tmp_file = path + ".tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_file, path)
    except Exception as e:
        print(f"Erreur lors de la sauvegarde JSON atomique : {e}")


def safe_write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


# ============================================================
# Download
# ============================================================
def download_feed(name: str, url: str) -> Dict[str, Any]:
    print(f"[+] Download: {name} -> {url}")
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()

    content_type = r.headers.get("Content-Type", "")
    last_modified = r.headers.get("Last-Modified")
    etag = r.headers.get("ETag")

    text = r.text

    raw_info = {
        "feed_name": name,
        "url": url,
        "downloaded_at": utc_now_iso(),
        "http_status": r.status_code,
        "content_type": content_type,
        "last_modified": last_modified,
        "etag": etag,
        "line_count": len(text.splitlines()),
        "text": text,
    }
    return raw_info


# ============================================================
# Parse Spamhaus TXT lists
# Format often looks like:
# 1.10.16.0/20 ; SBL256894
# comment lines start with ";"
# ============================================================
def detect_ioc_type(value: str) -> str:
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
        return "ipv6" if net.version == 6 else "ipv4"
    except ValueError:
        return "unknown"


def normalize_spamhaus_lines(feed_name: str, raw_text: str, source_url: str) -> List[Dict[str, Any]]:
    items = []
    lines = raw_text.splitlines()

    for idx, line in enumerate(lines, start=1):
        original_line = line
        line = line.strip()

        if not line:
            continue

        # Ignore comments/header lines
        if line.startswith(";"):
            continue

        # Expected pattern: "<network> ; <reference>"
        parts = [p.strip() for p in line.split(";") if p.strip()]

        if not parts:
            continue

        network = parts[0]
        reference = parts[1] if len(parts) > 1 else None

        ioc_type = detect_ioc_type(network)

        # Skip malformed entries
        if ioc_type == "unknown":
            continue

        try:
            net = ipaddress.ip_network(network, strict=False)
            first_ip = str(net.network_address)
            prefix = net.prefixlen
            total_addresses = net.num_addresses
            ip_version = net.version
        except ValueError:
            continue

        item = {
            "source": "spamhaus",
            "feed_name": feed_name,
            "source_url": source_url,
            "ioc_type": "ip_range",
            "ioc_subtype": ioc_type,
            "ioc_value": str(net),
            "reference": reference,
            "first_ip": first_ip,
            "prefix_length": prefix,
            "ip_version": ip_version,
            "total_addresses": total_addresses,
            "raw_line": original_line,
            "line_number": idx,
            "collected_at": utc_now_iso(),
        }
        items.append(item)

    return items


# ============================================================
# Deduplication
# ============================================================
def deduplicate_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []

    for item in items:
        key = (
            item.get("source"),
            item.get("feed_name"),
            item.get("ioc_value"),
            item.get("reference"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


# ============================================================
# Summary
# ============================================================
def build_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        "generated_at": utc_now_iso(),
        "total_items": len(items),
        "by_feed": {},
        "ipv4_count": 0,
        "ipv6_count": 0,
    }

    for item in items:
        feed = item["feed_name"]
        summary["by_feed"][feed] = summary["by_feed"].get(feed, 0) + 1

        if item["ioc_subtype"] == "ipv4":
            summary["ipv4_count"] += 1
        elif item["ioc_subtype"] == "ipv6":
            summary["ipv6_count"] += 1

    return summary


# ============================================================
# Main
# ============================================================
def main() -> None:
    tracking = load_tracking()
    last_date = tracking.get("latest_modified")
    if last_date:
        print(f"Dernière extraction (tracking) : {last_date}")
    else:
        print("Aucune exécution précédente trouvée.")

    print("Début de l'extraction...")

    all_items = []
    raw_metadata = []

    for feed_name, url in SPAMHAUS_FEEDS.items():
        try:
            raw = download_feed(feed_name, url)

            # Save raw metadata
            raw_meta = {
                k: v for k, v in raw.items() if k != "text"
            }
            raw_metadata.append(raw_meta)

            # Normalize
            normalized = normalize_spamhaus_lines(
                feed_name=feed_name,
                raw_text=raw["text"],
                source_url=url,
            )
            all_items.extend(normalized)

            print(f"[OK] {feed_name}: {len(normalized)} IOC")

        except requests.HTTPError as e:
            print(f"[ERROR] HTTP {feed_name}: {e}")
        except requests.RequestException as e:
            print(f"[ERROR] Network {feed_name}: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected {feed_name}: {e}")

    all_items = deduplicate_items(all_items)
    summary = build_summary(all_items)

    # Standard JSON Output: A flat list of records
    save_json_atomic(OUTPUT_JSON, all_items)

    print("\n========== SUMMARY ==========")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n[OK] Données enregistrées dans : {OUTPUT_JSON}")

    # Mise à jour du tracking
    now_str = utc_now_iso()
    tracking["latest_modified"] = now_str
    tracking["last_sync_success"] = now_str
    save_tracking_atomic(tracking)
    print(f"[OK] tracking.json mis à jour : {now_str}")

    # Nettoyage CSV
    if os.path.exists(OLD_TRACKING_FILE):
        try: os.remove(OLD_TRACKING_FILE)
        except: pass


if __name__ == "__main__":
    main()