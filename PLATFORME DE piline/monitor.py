"""
monitor.py — CTI Pipeline Status Monitor
Scans Sources_data/, reads tracking.json + data files, builds status.json.
"""

import os
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR  = os.path.join(BASE_DIR, "Sources_data")
OUTPUT_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "status.json")

# ── Identify source type ─────────────────────────────────────────────────────
CVE_KEYWORDS = ["cve", "nvd", "nvd_cisa", "vuln"]
IOC_KEYWORDS = ["abuse", "cins", "malware", "phish", "spam", "threat",
                 "virustotal", "feodo", "otx", "pulse", "openphish",
                 "pulsedive", "url", "threatfox"]

def determine_type(source_name: str, data_file: str | None) -> str:
    name_lower = source_name.lower()
    file_lower = os.path.basename(data_file).lower() if data_file else ""
    combined   = name_lower + " " + file_lower
    if any(k in combined for k in CVE_KEYWORDS):
        return "CVE"
    return "IOC"

# ── Find the primary data file ───────────────────────────────────────────────
EXCLUDED_FILES = {"tracking.json", "format_sources.json"}

def get_source_data_file(source_path: str) -> str | None:
    candidates = []
    for f in os.listdir(source_path):
        if not f.endswith(".json"):
            continue
        if f in EXCLUDED_FILES or f.endswith(".tmp"):
            continue
        full = os.path.join(source_path, f)
        candidates.append((full, os.path.getsize(full)))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]

# ── Fast record counter ───────────────────────────────────────────────────────
def count_records(file_path: str) -> int:
    """Count JSON array items without loading the entire file into memory."""
    if not file_path or not os.path.exists(file_path):
        return 0

    # Fast heuristic: count top-level '{' at depth=1 in the outer array
    count   = 0
    depth   = 0
    in_str  = False
    escape  = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for chunk in iter(lambda: fh.read(65536), ""):
                for ch in chunk:
                    if escape:
                        escape = False
                        continue
                    if ch == "\\" and in_str:
                        escape = True
                        continue
                    if ch == '"':
                        in_str = not in_str
                        continue
                    if in_str:
                        continue
                    if ch == "{":
                        depth += 1
                        if depth == 2:      # direct child of the root array
                            count += 1
                    elif ch == "}":
                        depth -= 1
        if count > 0:
            return count
    except Exception:
        pass

    # Fallback: load JSON normally
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            return 1
    except Exception:
        pass
    return 0

# ── Extract date range from tracking.json ────────────────────────────────────
def read_tracking(tracking_file: str) -> dict:
    defaults = {
        "last_sync":         "Jamais",
        "latest_modified":   "Inconnu",
        "earliest_modified": "Inconnu",
        "total_collected":   0,
        "status":            "Inactif",
    }
    if not os.path.exists(tracking_file):
        return defaults

    try:
        with open(tracking_file, "r", encoding="utf-8") as fh:
            t = json.load(fh)
    except Exception:
        defaults["status"] = "Erreur Tracking"
        return defaults

    # last_sync — try multiple field names
    last_sync = (
        t.get("last_run") or
        t.get("last_sync_success") or
        t.get("last_sync") or
        t.get("last_updated") or
        "Jamais"
    )

    latest   = t.get("latest_modified", t.get("latest_date", "Inconnu"))
    earliest = t.get("earliest_modified", t.get("earliest_date", "Inconnu"))
    total    = t.get("total_collected", t.get("total_entries", 0))

    return {
        "last_sync":         last_sync,
        "latest_modified":   latest,
        "earliest_modified": earliest,
        "total_collected":   total,
        "status":            "Actif",
    }

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(SOURCES_DIR):
        logging.error(f"Sources_data not found at {SOURCES_DIR}")
        return

    source_dirs = sorted([
        d for d in os.listdir(SOURCES_DIR)
        if os.path.isdir(os.path.join(SOURCES_DIR, d))
    ])

    print(f"\n{'='*50}")
    print(f"  CTI Monitor — Analyse de {len(source_dirs)} sources")
    print(f"{'='*50}\n")

    sources_info = []
    total_iocs   = 0
    total_cves   = 0

    for i, source_name in enumerate(source_dirs, 1):
        source_path   = os.path.join(SOURCES_DIR, source_name)
        tracking_file = os.path.join(source_path, "tracking.json")
        data_file     = get_source_data_file(source_path)
        source_type   = determine_type(source_name, data_file)

        tracking = read_tracking(tracking_file)

        # Date fallback from filesystem
        if tracking["latest_modified"] == "Inconnu" and data_file:
            try:
                mtime = os.path.getmtime(data_file)
                tracking["latest_modified"] = datetime.fromtimestamp(mtime).isoformat(timespec="seconds")
            except Exception:
                pass

        records = count_records(data_file)

        label = "🛡  IOC" if source_type == "IOC" else "🔴 CVE"
        print(f"  [{i:>2}/{len(source_dirs)}] {label}  {source_name:<30} → {records:>6} enregistrements")

        if source_type == "IOC":
            total_iocs += records
        else:
            total_cves += records

        sources_info.append({
            "name":              source_name,
            "type":              source_type,
            "status":            tracking["status"],
            "last_sync":         tracking["last_sync"],
            "latest_modified":   tracking["latest_modified"],
            "earliest_modified": tracking["earliest_modified"],
            "total_collected":   tracking["total_collected"],
            "records":           records,
            "data_file":         os.path.basename(data_file) if data_file else None,
        })

    dashboard = {
        "last_updated":  datetime.now().isoformat(timespec="seconds"),
        "total_sources": len(sources_info),
        "total_iocs":    total_iocs,
        "total_cves":    total_cves,
        "sources":       sources_info,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(dashboard, fh, indent=2, ensure_ascii=False)

    print(f"\n{'='*50}")
    print(f"  Terminé — status.json généré")
    print(f"  IOCs : {total_iocs:,}   |   CVEs : {total_cves:,}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
