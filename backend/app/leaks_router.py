import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File
import os
import json
from typing import List, Dict, Any
from datetime import datetime
import uuid
from dotenv import load_dotenv
load_dotenv()
from . import worker, database, schemas
import yaml

router = APIRouter(prefix="/api/leaks", tags=["leaks"])
db = database.db

_line_count_cache: dict = {}

def _count_lines_bg(path: str) -> None:
    """Count lines in background thread and store in cache."""
    import threading
    def _run():
        try:
            mtime = os.path.getmtime(path)
            key = (path, mtime)
            if key in _line_count_cache:
                return
            count = 0
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    count += chunk.count(b"\n")
            _line_count_cache[key] = max(0, count - 1)
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()

def _get_cached_line_count(path: str):
    """Return cached line count or None if not ready yet."""
    try:
        mtime = os.path.getmtime(path)
        return _line_count_cache.get((path, mtime))
    except Exception:
        return None

SETTINGS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "leak_data_integration", "config", "settings.yaml"))

# Purified Intelligence path
INTEL_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "leak_data_integration", "results", "leaks_intel.json"))

# Path absolu pour le fichier de session (racine du projet)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SESSION_PATH = os.path.join(PROJECT_ROOT, "telegram_leak_session")

from pydantic import BaseModel

class LeakStartRequest(BaseModel):
    channels: List[str] = None
    start_date: str = None

@router.post("/start")
async def start_leak_collection(background_tasks: BackgroundTasks, req: LeakStartRequest = None):
    req = req or LeakStartRequest()
    external_id = str(uuid.uuid4())
    new_run = {
        "run_id": external_id,
        "source_name": "Telegram Leaks",
        "source_type": "OSINT",
        "status_global": "running"
    }
    db.create_run(new_run)
    
    # Initialize the specific step for monitoring
    db.update_step(external_id, {
        "step_name": "Monitoring Telegram",
        "status": "pending",
        "ioc_count": 0,
        "cve_count": 0,
        "logs": [],
    })
    
    background_tasks.add_task(worker.execute_leak_collection_task, external_id, req.channels, req.start_date)
    return {"status": "success", "run_id": external_id}

# Global client store for auth (temporary)
AUTH_SESSIONS = {}

@router.get("/auth/config")
async def get_auth_config():
    import os
    env_phone = os.getenv("TELEGRAM_PHONE", "")
    return {"default_phone": env_phone}

@router.post("/auth/send-code")
async def send_code(phone: str = None):
    from telethon import TelegramClient
    import os
    
    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    env_phone = os.getenv("TELEGRAM_PHONE")
    
    # Use provided phone or fallback to .env
    target_phone = phone or env_phone
    
    if not target_phone:
        raise HTTPException(status_code=400, detail="Phone number not provided and not found in .env")
        
    if not api_id or not api_hash:
        raise HTTPException(status_code=400, detail="Missing API ID/Hash in .env")
        
    client = TelegramClient(SESSION_PATH, api_id, api_hash)
    await client.connect()
    
    try:
        # Request code
        res = await client.send_code_request(target_phone)
        AUTH_SESSIONS[target_phone] = {
            "phone_code_hash": res.phone_code_hash
        }
        await client.disconnect()
        return {"status": "success", "phone": target_phone, "phone_code_hash": res.phone_code_hash}
    except Exception as e:
        await client.disconnect()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auth/verify-code")
async def verify_code(phone: str, code: str, phone_code_hash: str):
    from telethon import TelegramClient
    import os
    
    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    
    session_data = AUTH_SESSIONS.get(phone)
    if not session_data:
        raise HTTPException(status_code=400, detail="No active auth session found for this phone. Please request a new code.")
        
    client = TelegramClient(SESSION_PATH, api_id, api_hash)
    await client.connect()
        
    try:
        await client.sign_in(phone, code, phone_code_hash=phone_code_hash)
        if await client.is_user_authorized():
            return {"status": "success", "message": "Authenticated successfully"}
        else:
            return {"status": "error", "message": "Failed to authorize"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.disconnect()
        if phone in AUTH_SESSIONS:
            del AUTH_SESSIONS[phone]

@router.get("/status")
async def get_telegram_status():
    from telethon import TelegramClient
    import os
    
    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    
    if not api_id or not api_hash:
        return {"connected": False, "reason": "Missing credentials"}
        
    try:
        client = TelegramClient(SESSION_PATH, api_id, api_hash)
        await client.connect()
        authorized = await client.is_user_authorized()
        await client.disconnect()
        return {"connected": authorized}
    except Exception as e:
        error_str = str(e).lower()
        if "database is locked" in error_str:
            # Si la base est verrouillée, c'est probablement que le collecteur tourne déjà (donc la session est valide et utilisée)
            return {"connected": True, "reason": "database locked by another process (collector is likely running)"}
        return {"connected": False, "reason": str(e)}

def _normalize_channel(ch) -> dict:
    """Normalize channel entry to dict format regardless of old string or new dict format."""
    if isinstance(ch, str):
        return {"url": ch, "name": "", "description": "", "category": "", "risk_level": "unknown", "member_count": 0, "language": "", "country": ""}
    return {
        "url": ch.get("url", ""),
        "name": ch.get("name", ""),
        "description": ch.get("description", ""),
        "category": ch.get("category", ""),
        "risk_level": ch.get("risk_level", "unknown"),
        "member_count": ch.get("member_count", 0),
        "language": ch.get("language", ""),
        "country": ch.get("country", ""),
    }

def _load_config():
    with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _save_config(config):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

@router.get("/channels")
async def get_telegram_channels():
    if not os.path.exists(SETTINGS_FILE):
        return []
    try:
        config = _load_config()
        raw = config.get("telegram", {}).get("channels", [])
        return [_normalize_channel(ch) for ch in raw]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/channels")
async def add_telegram_channel(
    url: str,
    name: str = "",
    description: str = "",
    category: str = "",
    risk_level: str = "unknown",
    member_count: int = 0,
    language: str = "",
    country: str = "",
):
    if not os.path.exists(SETTINGS_FILE):
        raise HTTPException(status_code=404, detail="Settings file not found")
    try:
        config = _load_config()
        if "telegram" not in config: config["telegram"] = {}
        if "channels" not in config["telegram"]: config["telegram"]["channels"] = []

        channels = config["telegram"]["channels"]
        existing_urls = [_normalize_channel(ch)["url"] for ch in channels]

        if url not in existing_urls:
            new_entry = {"url": url, "name": name, "description": description, "category": category, "risk_level": risk_level, "member_count": member_count, "language": language, "country": country}
            config["telegram"]["channels"].append(new_entry)
            _save_config(config)

        return {"status": "success", "channels": [_normalize_channel(ch) for ch in config["telegram"]["channels"]]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/channels")
async def update_telegram_channel(
    url: str,
    name: str = "",
    description: str = "",
    category: str = "",
    risk_level: str = "unknown",
    member_count: int = 0,
    language: str = "",
    country: str = "",
):
    if not os.path.exists(SETTINGS_FILE):
        raise HTTPException(status_code=404, detail="Settings file not found")
    try:
        config = _load_config()
        channels = config.get("telegram", {}).get("channels", [])
        found = False
        for i, ch in enumerate(channels):
            if _normalize_channel(ch)["url"] == url:
                channels[i] = {"url": url, "name": name, "description": description, "category": category, "risk_level": risk_level, "member_count": member_count, "language": language, "country": country}
                found = True
                break
        if not found:
            raise HTTPException(status_code=404, detail="Channel not found")
        config["telegram"]["channels"] = channels
        _save_config(config)
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/channels")
async def remove_telegram_channel(url: str):
    if not os.path.exists(SETTINGS_FILE):
        raise HTTPException(status_code=404, detail="Settings file not found")
    try:
        config = _load_config()
        if "telegram" in config and "channels" in config["telegram"]:
            config["telegram"]["channels"] = [
                ch for ch in config["telegram"]["channels"]
                if _normalize_channel(ch)["url"] != url
            ]
            _save_config(config)
        return {"status": "success", "channels": [_normalize_channel(ch) for ch in config.get("telegram", {}).get("channels", [])]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

LEAKS_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "leaks"))

@router.get("/")
def get_leaks():
    all_leaks = []
    if not os.path.exists(LEAKS_DATA_DIR):
        return []

    for channel in os.listdir(LEAKS_DATA_DIR):
        channel_path = os.path.join(LEAKS_DATA_DIR, channel)
        if not os.path.isdir(channel_path):
            continue
        
        for date_dir in os.listdir(channel_path):
            date_path = os.path.join(channel_path, date_dir)
            if not os.path.isdir(date_path):
                continue
            
            leaks_file = os.path.join(date_path, "leaks.json")
            if os.path.exists(leaks_file):
                try:
                    with open(leaks_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_leaks.extend(data)
                except Exception as e:
                    print(f"Error reading {leaks_file}: {e}")
    
    # Sort by date descending
    all_leaks.sort(key=lambda x: x.get("date", ""), reverse=True)
    return all_leaks

@router.get("/stats")
def get_leak_stats():
    # Use purified intel for stats as it's consolidated and verified
    leaks = []
    if os.path.exists(INTEL_FILE):
        try:
            with open(INTEL_FILE, "r", encoding="utf-8") as f:
                leaks = json.load(f)
        except Exception as e:
            print(f"Error reading {INTEL_FILE}: {e}")
    
    # If intel is empty, fallback to raw leaks for backward compatibility or empty state
    if not leaks:
        leaks = get_leaks()
        is_intel = False
    else:
        is_intel = True

    stats = {
        "total": len(leaks),
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "by_type": {},
        "by_channel": {}
    }
    
    for leak in leaks:
        if is_intel:
            metadata = leak.get("leak_metadata", {})
            severity = metadata.get("severity", "low").lower()
            leak_type = metadata.get("leak_type", "unknown")
            channel = leak.get("source_channel", "unknown")
        else:
            analysis = leak.get("analysis", {})
            severity = analysis.get("severity", "low").lower()
            leak_type = analysis.get("leak_type", "unknown")
            channel = leak.get("channel", "unknown")
        
        stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        stats["by_type"][leak_type] = stats["by_type"].get(leak_type, 0) + 1
        stats["by_channel"][channel] = stats["by_channel"].get(channel, 0) + 1
        
    return stats

@router.get("/intel")
def get_purified_intel():
    if os.path.exists(INTEL_FILE):
        try:
            with open(INTEL_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return []

@router.get("/intel/{intel_id}/bulletin")
def get_leak_bulletin(intel_id: str):
    import sys
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
        
    from leak_data_integration.core.reporter import LeakReporter
    reporter = LeakReporter(INTEL_FILE)
    content = reporter.generate_individual_bulletin(intel_id)
    if not content:
        raise HTTPException(status_code=404, detail="Intel record not found")
    return {"content": content}

@router.get("/intel/{intel_id}/bulletin/pdf")
def get_pdf_bulletin(intel_id: str):
    from fastapi.responses import FileResponse
    # Use the PDF generation module we just created
    import sys
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
        
    try:
        from leak_data_integration.core.reporter import LeakReporter
    except ImportError:
        raise HTTPException(status_code=500, detail="Leak reporting module not found")
        
    reporter = LeakReporter(INTEL_FILE)
    
    # Try generating it
    INTEGRATION_DIR = os.path.join(PROJECT_ROOT, "leak_data_integration")
    pdf_path = os.path.join(INTEGRATION_DIR, "reports", f"bulletin_{intel_id}.pdf")
    success = reporter.generate_pdf_bulletin(intel_id, pdf_path)
    
    if not success or not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to generate PDF bulletin")
        
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"bulletin_{intel_id}.pdf")

@router.delete("/intel/{intel_id}")
def delete_leak(intel_id: str):
    """Deletes a leak and all its associated physical files and PDFs."""
    if not os.path.exists(INTEL_FILE):
        raise HTTPException(status_code=404, detail="Intel file not found")
        
    with open(INTEL_FILE, "r", encoding="utf-8") as f:
        leaks = json.load(f)
        
    leak_index = next((i for i, leak in enumerate(leaks) if leak.get("intel_id") == intel_id), None)
    if leak_index is None:
        raise HTTPException(status_code=404, detail="Leak not found")
        
    leak = leaks[leak_index]
    
    # Delete extracted files physically
    base_data = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "leaks"))
    for file_path in leak.get("extracted_files", []):
        abs_path = os.path.join(base_data, file_path)
        try:
            if os.path.exists(abs_path):
                os.remove(abs_path)
        except Exception as e:
            print(f"Failed to delete file {abs_path}: {e}")
            
    # Delete the PDF bulletin if it exists
    safe_id = "".join([c if c.isalnum() or c in "-_" else "_" for c in intel_id])
    pdf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "reports", "fuite", f"Bulletin_Fuite_{safe_id}.pdf"))
    try:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
    except Exception as e:
        print(f"Failed to delete PDF {pdf_path}: {e}")
        
    # Remove from JSON
    leaks.pop(leak_index)
    with open(INTEL_FILE, "w", encoding="utf-8") as f:
        json.dump(leaks, f, indent=4, ensure_ascii=False)
        
    return {"status": "success", "message": f"Leak {intel_id} and associated files deleted."}

@router.get("/csv/view")
def view_csv(path: str, limit: int = 50, offset: int = 0):
    # Security: Ensure path is within the data directory
    base_data = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
    
    # Support both relative paths (from data/) and absolute-style paths with leaks prefix
    candidate = os.path.abspath(os.path.join(base_data, path))
    # Also try directly if it looks like a leaks sub-path
    if not os.path.exists(candidate):
        candidate2 = os.path.abspath(os.path.join(base_data, "leaks", path))
        if os.path.exists(candidate2):
            candidate = candidate2

    abs_path = candidate

    if not abs_path.startswith(base_data):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    ext = os.path.splitext(abs_path)[1].lower()

    # ── TXT files: return as plain lines ──────────────────────────────
    if ext == ".txt":
        for enc in ("utf-8", "utf-16", "utf-16-le", "latin-1", "cp1252"):
            try:
                with open(abs_path, "r", encoding=enc) as f:
                    lines = f.readlines()[:500]  # Limit to 500 lines
                content = "".join(lines)
                # If we still see lots of null bytes or it looks like UTF-16 misread, we continue
                if "\x00" in content and enc == "utf-8":
                    continue
                return {"type": "text", "content": content, "lines": len(lines)}
            except (UnicodeDecodeError, UnicodeError):
                continue
        raise HTTPException(status_code=500, detail="Could not decode text file")

    # ── Excel files: parse using pandas ─────────────────────────────
    if ext in [".xlsx", ".xls"]:
        try:
            import pandas as pd
            df = pd.read_excel(abs_path).head(200)
            
            # Infer column types (use pandas dtypes — no exceptions)
            col_types = {}
            for col in df.columns:
                dtype = df[col].dtype
                if pd.api.types.is_numeric_dtype(dtype):
                    col_types[str(col)] = "number"
                elif pd.api.types.is_datetime64_any_dtype(dtype):
                    col_types[str(col)] = "date"
                else:
                    col_types[str(col)] = "text"

            # Sanitize for JSON
            import math
            def sanitize(val):
                if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                    return None
                if isinstance(val, (datetime, pd.Timestamp)):
                    return val.isoformat()
                return val

            records = [
                {str(k): sanitize(v) for k, v in row.items()}
                for row in df.to_dict(orient="records")
            ]

            payload = {
                "type": "csv", # Keep type as csv for the frontend to use the same component
                "data": records,
                "columns": [str(c) for c in df.columns],
                "col_types": col_types,
                "detected_sep": "n/a",
                "encoding": "binary/excel",
                "total_rows": len(df),
            }
            from fastapi.responses import JSONResponse
            return JSONResponse(content=payload)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error reading Excel file: {str(e)}")

    # ── CSV files: pure Python csv module — reads exactly 200 rows, no pandas ──
    try:
        import csv as csv_mod
        from fastapi.responses import JSONResponse

        # ── Detect encoding from first 8KB ───────────────────────────
        ENCODINGS = ("utf-8", "utf-8-sig", "latin-1", "cp1252")
        used_enc = "latin-1"  # latin-1 never fails, safe fallback
        for enc in ("utf-8", "utf-8-sig"):
            try:
                with open(abs_path, "r", encoding=enc) as f:
                    f.read(8192)
                used_enc = enc
                break
            except UnicodeDecodeError:
                continue

        # Lance le comptage en arrière-plan (résultat mis en cache)
        _count_lines_bg(abs_path)

        # ── Read first 4KB to detect separator ───────────────────────
        with open(abs_path, "r", encoding=used_enc, errors="replace") as f:
            head = f.read(4096)

        first_line = head.splitlines()[0] if head else ""
        sep_counts = {",": first_line.count(","), ";": first_line.count(";"),
                      "\t": first_line.count("\t"), "|": first_line.count("|")}
        detected_sep = max(sep_counts, key=sep_counts.get) if any(sep_counts.values()) else ","

        # ── Read `limit` rows starting at `offset` ───────────────────
        MAX_ROWS = max(1, limit)
        SKIP = max(0, offset)
        columns = []
        records = []

        with open(abs_path, "r", encoding=used_enc, errors="replace", newline="") as f:
            reader = csv_mod.reader(f, delimiter=detected_sep)
            raw_header = next(reader, [])
            columns = [str(c).strip().strip('"') for c in raw_header]
            n_cols = len(columns)
            skipped = 0
            for row in reader:
                if not any(row):
                    continue
                if skipped < SKIP:
                    skipped += 1
                    continue
                if len(records) >= MAX_ROWS:
                    break
                padded = row + [""] * max(0, n_cols - len(row))
                records.append({columns[i]: padded[i].strip('"') for i in range(n_cols)})

        # ── Infer col types from first non-empty value ────────────────
        col_types = {}
        for col in columns:
            val = next((r[col] for r in records if r.get(col, "").strip()), "")
            if not val:
                col_types[col] = "empty"
            elif "@" in val and "." in val.split("@")[-1]:
                col_types[col] = "email"
            elif val.startswith(("http://", "https://")):
                col_types[col] = "url"
            else:
                try:
                    float(val.replace(",", ".").replace(" ", ""))
                    col_types[col] = "number"
                except ValueError:
                    col_types[col] = "text"

        payload = {
            "type": "csv",
            "data": records,
            "columns": columns,
            "col_types": col_types,
            "detected_sep": detected_sep if detected_sep != "\t" else "\\t",
            "encoding": used_enc,
            "total_rows": len(records),
            "offset": SKIP,
            "file_total_rows": _get_cached_line_count(abs_path),
        }
        return JSONResponse(content=payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")

@router.post("/reanalyze/{channel}/{leak_id}")
async def reanalyze_leak(channel: str, leak_id: str):
    # This would trigger a re-analysis with the AI agent
    # For now, let's just simulate or find the file and update it
    # Implementation depends on how we want to trigger the analyzer
    return {"status": "success", "message": "Re-analysis scheduled"}

@router.post("/csv/upload")
async def upload_csv(file: UploadFile = File(...)):
    if not file.filename.endswith((".csv", ".txt")):
        raise HTTPException(status_code=400, detail="Only CSV or TXT files are allowed")
    
    base_data = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "leaks", "uploads"))
    os.makedirs(base_data, exist_ok=True)
    
    file_path = os.path.join(base_data, file.filename)
    
    try:
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)
        return {"status": "success", "path": f"uploads/{file.filename}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {e}")

@router.post("/csv/analyze")
async def analyze_csv(path: str):
    base_data = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
    candidate = os.path.abspath(os.path.join(base_data, path))
    if not os.path.exists(candidate):
        candidate2 = os.path.abspath(os.path.join(base_data, "leaks", path))
        if os.path.exists(candidate2):
            candidate = candidate2

    abs_path = candidate

    if not abs_path.startswith(base_data):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    # ── Read full file for AI (lines taken from original file on disk) ──
    MAX_SIZE_MB = 500
    file_size_mb = os.path.getsize(abs_path) / (1024 * 1024)
    if file_size_mb > MAX_SIZE_MB:
        raise HTTPException(
            status_code=413,
            detail=f"File too large for AI analysis ({file_size_mb:.1f} MB > {MAX_SIZE_MB} MB limit)"
        )

    try:
        raw_lines = []
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                with open(abs_path, "r", encoding=enc, errors="ignore") as f:
                    raw_lines = f.readlines()   # Full file — all original lines
                break
            except Exception:
                continue
        sample_data = "".join(raw_lines)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file for analysis: {e}")

    # Initialize analyzer
    import sys
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)

    from leak_data_integration.core.analyzer import LeakAnalyzer
    analyzer = LeakAnalyzer()

    file_name = os.path.basename(abs_path)
    total_lines = len(raw_lines)
    text_context = (
        f"File name: {file_name}\n"
        f"File size: {file_size_mb:.2f} MB\n"
        f"Total lines: {total_lines}\n"
        f"This is a standalone CSV/TXT file uploaded for security analysis."
    )

    try:
        analysis_result = await analyzer.analyze_leak(text=text_context, file_context=sample_data)
        return {"status": "success", "analysis": analysis_result, "meta": {"total_lines": total_lines, "size_mb": round(file_size_mb, 2)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Analysis failed: {e}")

