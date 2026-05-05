from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File
import os
import json
from typing import List, Dict, Any
from datetime import datetime
import uuid
from dotenv import load_dotenv
load_dotenv()
from . import worker, database, schemas

router = APIRouter(prefix="/api/leaks", tags=["leaks"])
db = database.db

# Purified Intelligence path
INTEL_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "leak_data_integration", "results", "leaks_intel.json"))

# Path absolu pour le fichier de session (racine du projet)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SESSION_PATH = os.path.join(PROJECT_ROOT, "telegram_leak_session")

@router.post("/start")
async def start_leak_collection(background_tasks: BackgroundTasks):
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
    
    background_tasks.add_task(worker.execute_leak_collection_task, external_id)
    return {"status": "success", "run_id": external_id}

# Global client store for auth (temporary)
AUTH_SESSIONS = {}

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
            "client": client,
            "phone_code_hash": res.phone_code_hash
        }
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
        # Try to reconnect if session lost in memory
        client = TelegramClient(SESSION_PATH, api_id, api_hash)
        await client.connect()
    else:
        client = session_data["client"]
        
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
        return {"connected": False, "reason": str(e)}

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
    leaks = get_leaks()
    stats = {
        "total": len(leaks),
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "by_type": {},
        "by_channel": {}
    }
    
    for leak in leaks:
        analysis = leak.get("analysis", {})
        severity = analysis.get("severity", "low")
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
    INTEGRATION_DIR = os.path.join(PROJECT_ROOT, "leak_data_integration")
    if INTEGRATION_DIR not in sys.path:
        sys.path.insert(0, INTEGRATION_DIR)
        
    from core.reporter import LeakReporter
    reporter = LeakReporter(INTEL_FILE)
    content = reporter.generate_individual_bulletin(intel_id)
    if not content:
        raise HTTPException(status_code=404, detail="Intel record not found")
    return {"content": content}

@router.get("/intel/{intel_id}/bulletin/pdf")
async def get_leak_bulletin_pdf(intel_id: str):
    import sys
    INTEGRATION_DIR = os.path.join(PROJECT_ROOT, "leak_data_integration")
    if INTEGRATION_DIR not in sys.path:
        sys.path.insert(0, INTEGRATION_DIR)
        
    from core.reporter import LeakReporter
    reporter = LeakReporter(INTEL_FILE)
    
    # Generate unique filename
    pdf_path = os.path.join(INTEGRATION_DIR, "reports", f"bulletin_{intel_id}.pdf")
    success = reporter.generate_pdf_bulletin(intel_id, pdf_path)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to generate PDF bulletin")
        
    from fastapi.responses import FileResponse
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"bulletin_{intel_id}.pdf")

@router.get("/csv/view")
def view_csv(path: str):
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
        for enc in ("utf-8", "latin-1", "cp1252"):
            try:
                with open(abs_path, "r", encoding=enc) as f:
                    lines = f.readlines()[:500]  # Limit to 500 lines
                content = "".join(lines)
                return {"type": "text", "content": content, "lines": len(lines)}
            except UnicodeDecodeError:
                continue
        raise HTTPException(status_code=500, detail="Could not decode text file")

    # ── CSV files: auto-detect separator + parse ──────────────────────
    try:
        import pandas as pd
        import csv as csv_mod
        from io import StringIO

        ENCODINGS = ("utf-8", "utf-8-sig", "latin-1", "cp1252")
        raw_text = None
        used_enc = "utf-8"
        for enc in ENCODINGS:
            try:
                with open(abs_path, "r", encoding=enc) as f:
                    raw_text = f.read()
                used_enc = enc
                break
            except UnicodeDecodeError:
                continue

        if raw_text is None:
            raise HTTPException(status_code=500, detail="Could not decode file")

        # ── Auto-detect separator ────────────────────────────────────
        detected_sep = ","
        sample = "\n".join(raw_text.splitlines()[:20])
        try:
            sniffer = csv_mod.Sniffer()
            dialect = sniffer.sniff(sample, delimiters=",;\t|:")
            detected_sep = dialect.delimiter
        except csv_mod.Error:
            first_line = raw_text.splitlines()[0] if raw_text.splitlines() else ""
            candidates = {
                ",":  first_line.count(","),
                ";":  first_line.count(";"),
                "\t": first_line.count("\t"),
                "|":  first_line.count("|"),
                ":":  first_line.count(":"),
            }
            best = max(candidates, key=candidates.get)
            detected_sep = best if candidates[best] > 0 else ","

        # ── Parse ────────────────────────────────────────────────────
        df = pd.read_csv(StringIO(raw_text), sep=detected_sep,
                         engine="python", on_bad_lines="skip").head(200)

        # ── Infer column types ───────────────────────────────────────
        col_types = {}
        for col in df.columns:
            series = df[col].dropna()
            if series.empty:
                col_types[str(col)] = "empty"; continue
            try:
                pd.to_numeric(series); col_types[str(col)] = "number"; continue
            except Exception:
                pass
            try:
                pd.to_datetime(series, infer_datetime_format=True, errors="raise")
                col_types[str(col)] = "date"; continue
            except Exception:
                pass
            sample_val = str(series.iloc[0])
            if "@" in sample_val and "." in sample_val.split("@")[-1]:
                col_types[str(col)] = "email"; continue
            if sample_val.startswith(("http://", "https://")):
                col_types[str(col)] = "url"; continue
            col_types[str(col)] = "text"

        # ── Sanitize NaN / Inf (JSON-incompatible float values) ─────
        import math
        from fastapi.responses import JSONResponse

        def sanitize(val):
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                return None
            return val

        records = [
            {k: sanitize(v) for k, v in row.items()}
            for row in df.to_dict(orient="records")
        ]

        payload = {
            "type": "csv",
            "data": records,
            "columns": list(df.columns),
            "col_types": col_types,
            "detected_sep": detected_sep if detected_sep != "\t" else "\\t",
            "encoding": used_enc,
            "total_rows": len(df),
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

    # Read a sample of the CSV
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            sample_data = "".join(f.readlines()[:50])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file for analysis: {e}")

    # Initialize analyzer
    import sys
    INTEGRATION_DIR = os.path.join(PROJECT_ROOT, "leak_data_integration")
    if INTEGRATION_DIR not in sys.path:
        sys.path.insert(0, INTEGRATION_DIR)
        
    from core.analyzer import LeakAnalyzer
    analyzer = LeakAnalyzer()
    
    file_name = os.path.basename(abs_path)
    text_context = f"File name: {file_name}\nThis is a standalone CSV file uploaded for analysis."
    
    try:
        analysis_result = await analyzer.analyze_leak(text=text_context, file_context=sample_data)
        return {"status": "success", "analysis": analysis_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Analysis failed: {e}")

