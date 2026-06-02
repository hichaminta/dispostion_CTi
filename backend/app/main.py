import asyncio
import json
import os
import sys
import time
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from typing import List
import uuid

# Ajouter la racine du projet au path pour accéder à misp_integration, enrichment, etc.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ==============================================================================
# CORRECTION WINDOWS : Force ProactorEventLoopPolicy pour les sous-processus
# Doit être fait le plus tôt possible, avant toute création de boucle.
# ==============================================================================
if sys.platform == 'win32':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        print("[INIT] Windows Proactor Event Loop Policy set.")
    except Exception as e:
        print(f"[INIT] Failed to set Proactor policy: {e}")

from datetime import datetime, timedelta
from . import schemas, database, websockets, worker, leaks_router
from .admin import router as admin_router
from .database import db

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_cve_ioc"))
ENRICHMENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_enrichment"))
MITRE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation")) # Use correlation output for some stats too
CORRELATION_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation"))
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dashboard"))

app = FastAPI(title="CTI Pipeline Tracker API")
app.include_router(leaks_router.router)
app.include_router(admin_router)

class ChangePasswordRequest(schemas.BaseModel):
    username: str
    old_password: str
    new_password: str

@app.post("/api/auth/change-password")
def change_password(req: ChangePasswordRequest):
    # Local import to avoid circular dependency issues if any
    from .auth import keycloak_openid, get_keycloak_admin
    # Use get_keycloak_admin directly
    admin_client = get_keycloak_admin()
    
    try:
        keycloak_openid.token(req.username, req.old_password)
    except Exception as e:
        err_str = str(e)
        if "Account is not fully set up" in err_str:
            pass # Expected if password change is required
        elif "Invalid user credentials" in err_str:
            raise HTTPException(status_code=400, detail="Ancien mot de passe incorrect")
        elif "invalid_grant" in err_str:
             raise HTTPException(status_code=400, detail="Ancien mot de passe incorrect")

    users = admin_client.get_users({"username": req.username})
    if not users:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    user_id = users[0]["id"]
    
    admin_client.set_user_password(user_id=user_id, password=req.new_password, temporary=False)
    
    # Explicitly clear ALL required actions (including UPDATE_PASSWORD)
    # We send only the requiredActions field to avoid Keycloak rejecting read-only fields
    admin_client.update_user(user_id, {"requiredActions": []})
        
    return {"status": "success"}

app.mount("/results", StaticFiles(directory=DASHBOARD_DIR, html=True), name="results")
app.mount("/data", StaticFiles(directory=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))), name="data")
app.mount("/bulletins", StaticFiles(directory=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bultein_de_security"))), name="bulletins")
GEO_STATS_CACHE = {"data": [], "last_updated": 0}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/runs", response_model=List[schemas.Run])
def get_runs():
    return db.get_runs()[::-1]

@app.get("/runs/{run_id}", response_model=schemas.Run)
def get_run(run_id: int):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.get("/runs/{run_id}/logs")
def get_run_logs(run_id: int, step: str = None):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    logs = db.get_logs(run["run_id"], step_name=step)
    return {"run_id": run_id, "step": step, "logs": logs}

@app.post("/runs", response_model=schemas.Run)
async def create_run(run_in: schemas.RunCreate, background_tasks: BackgroundTasks):
    external_id = str(uuid.uuid4())
    new_run = {
        "run_id": external_id,
        "source_name": run_in.source_name,
        "source_type": run_in.source_type,
        "status_global": "running"
    }
    db.create_run(new_run)
    steps = ["Collecte", "Extraction CVE / IOC", "AbuseIPDB Enrichment", "VirusTotal Enrichment", "Geolocalisation", "URLScan", "Enrichissement CVE", "Classification", "MITRE Mapping", "Corrélation SOC", "Export STIX", "Intégration MISP"]
    for step_name in steps:
        db.update_step(external_id, {
            "step_name": step_name,
            "status": "pending",
            "ioc_count": 0,
            "cve_count": 0,
            "logs": [],
        })
    background_tasks.add_task(worker.execute_pipeline_task, external_id, run_in.source_name)
    return db.get_run_by_external_id(external_id)

@app.post("/runs/enrich", response_model=schemas.Run)
async def create_enrichment_run(run_in: schemas.RunCreate, background_tasks: BackgroundTasks):
    external_id = str(uuid.uuid4())
    new_run = {
        "run_id": external_id,
        "source_name": run_in.source_name,
        "source_type": run_in.source_type,
        "status_global": "running"
    }
    db.create_run(new_run)
    
    # Single step for targeted enrichment
    db.update_step(external_id, {
        "step_name": "Enrichissement",
        "status": "pending",
        "ioc_count": 0,
        "cve_count": 0,
        "logs": [],
    })
    
    background_tasks.add_task(worker.execute_enrichment_task, external_id, run_in.source_name)
    return db.get_run_by_external_id(external_id)

@app.post("/runs/{run_id}/stop")
async def stop_run(run_id: int):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    external_id = run["run_id"]
    success = worker.terminate_run(external_id)
    
    if success:
        # Update database status
        db.update_run(external_id, {"status_global": "failed"})
        # Notify via WebSocket
        await websockets.manager.broadcast({
            "type": "run_complete",
            "run_id": external_id,
            "status": "failed",
            "message": "Arrêté par l'utilisateur"
        })
        return {"status": "success", "message": "Pipeline arrêté"}
    else:
        return {"status": "error", "message": "Aucun processus actif trouvé pour ce run"}

@app.post("/runs/targeted", response_model=schemas.Run)
async def create_targeted_run(run_in: schemas.RunCreate, step_name: str, background_tasks: BackgroundTasks):
    external_id = str(uuid.uuid4())
    new_run = {
        "run_id": external_id,
        "source_name": run_in.source_name,
        "source_type": run_in.source_type,
        "status_global": "running"
    }
    db.create_run(new_run)

    # For unified enrichment, pre-create all individual phase steps so dots appear immediately
    ENRICHMENT_SUB_STEPS = [
        "AbuseIPDB Enrichment", "VirusTotal Enrichment", "Geolocalisation",
        "URLScan", "Enrichissement CVE", "Classification", "MITRE Mapping",
    ]
    is_unified_enrich = (step_name == "Enrichissement" and run_in.source_name == "Unified Extraction")
    steps_to_init = ENRICHMENT_SUB_STEPS if is_unified_enrich else [step_name]

    run_obj = None
    for s in steps_to_init:
        run_obj = db.update_step(external_id, {
            "step_name": s,
            "status": "pending",
            "ioc_count": 0,
            "cve_count": 0,
            "logs": [],
        })

    background_tasks.add_task(worker.execute_targeted_task, external_id, run_in.source_name, step_name)
    return run_obj

@app.get("/stats")
def get_stats():
    runs = db.get_runs()
    total_ioc, total_cve = worker._count_ioc_cve("Unified Extraction")
    
    durations = []
    for r in runs:
        if r.get("status_global") == "success" and r.get("created_at") and r.get("updated_at"):
            try:
                start = datetime.fromisoformat(r["created_at"])
                end = datetime.fromisoformat(r["updated_at"])
                durations.append((end - start).total_seconds())
            except: pass

    # MISP Sync Status
    misp_tracking_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "misp_integration", "tracking", "misp_tracking.json"))
    misp_status = None
    if os.path.exists(misp_tracking_path):
        try:
            with open(misp_tracking_path, "r", encoding="utf-8") as f:
                misp_status = json.load(f)
        except: pass

    return {
        "total_ioc": total_ioc,
        "total_cve": total_cve,
        "total_runs": len(runs),
        "success_runs": sum(1 for r in runs if r.get("status_global") == "success"),
        "running_runs": sum(1 for r in runs if r.get("status_global") == "running"),
        "avg_duration_sec": round(sum(durations) / len(durations)) if durations else 0,
        "misp_sync": misp_status
    }

@app.get("/api/misp/status")
def get_misp_status():
    misp_tracking_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "misp_integration", "tracking", "misp_tracking.json"))
    if not os.path.exists(misp_tracking_path):
        return {"error": "Tracking file not found"}
    try:
        with open(misp_tracking_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/stats/countries")
def get_country_stats():
    global GEO_STATS_CACHE
    now = time.time()
    if GEO_STATS_CACHE["data"] and (now - GEO_STATS_CACHE["last_updated"] < 300):
        return GEO_STATS_CACHE["data"]

    country_counts = {}
    if os.path.exists(ENRICHMENT_DIR):
        for fn in os.listdir(ENRICHMENT_DIR):
            if not fn.endswith("_enriched.json"): continue
            filepath = os.path.join(ENRICHMENT_DIR, fn)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
                for record in records:
                    record_countries = set()
                    for ioc in record.get("iocs", []):
                        geos = ioc.get("ioc_enrichment", {}).get("geography", [])
                        if isinstance(geos, list):
                            for g in geos: record_countries.add(g)
                        elif geos:
                            record_countries.add(geos)
                    
                    geos_adv = record.get("enrichment", {}).get("nlp_advanced", {}).get("geography", [])
                    if isinstance(geos_adv, list):
                        for g in geos_adv: record_countries.add(g)
                    elif geos_adv:
                        record_countries.add(geos_adv)
                    
                    for country in record_countries:
                        if country and len(str(country)) > 1:
                            country_counts[country] = country_counts.get(country, 0) + 1
            except:
                continue
    
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    result = [{"country": c, "count": n} for c, n in sorted_countries[:12]]
    
    GEO_STATS_CACHE["data"] = result
    GEO_STATS_CACHE["last_updated"] = now
    return result

# ──────────────────────────────────────────────────────────────────────────────
# EXTRACTION ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/extracted/sources")
def get_extracted_sources():
    sources = []
    if os.path.exists(OUTPUT_DIR):
        for src_name, info in worker.SOURCE_MAP.items():
            filepath = os.path.join(OUTPUT_DIR, info["output"])
            if os.path.exists(filepath):
                stats = os.stat(filepath)
                sources.append({
                    "id": info["id"],
                    "name": src_name,
                    "file": info["output"],
                    "size": stats.st_size,
                    "last_modified": stats.st_mtime
                })
    return sources

@app.get("/api/extracted/data/{source_id}")
def get_extracted_data(source_id: str, page: int = 1, limit: int = 50, search: str = None, ioc_type: str = None):
    info = None
    for src_name, src_info in worker.SOURCE_MAP.items():
        if src_info["id"] == source_id:
            info = src_info
            break
    
    if not info:
        raise HTTPException(status_code=404, detail="Source not found")
        
    filepath = os.path.join(OUTPUT_DIR, info["output"])
    if not os.path.exists(filepath):
        return {"data": [], "total": 0, "page": page, "limit": limit}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            all_data = json.load(f)
            
        # 1. Type Filtering
        if ioc_type:
            t_low = ioc_type.lower()
            if t_low == "cve":
                all_data = [d for d in all_data if d.get("cves")]
            else:
                all_data = [
                    d for d in all_data 
                    if any(i.get("type", "").lower() == t_low for i in d.get("iocs", []))
                ]

        # 2. Search Filtering
        if search:
            search_low = search.lower()
            all_data = [
                d for d in all_data 
                if search_low in str(d.get("record_id", "")).lower() or 
                   any(search_low in str(t).lower() for t in d.get("tags", [])) or
                   search_low in str(d.get("raw_text", "")).lower()
            ]
            
        total = len(all_data)
        start = (page - 1) * limit
        end = start + limit
        return {
            "data": all_data[start:end],
            "total": total,
            "page": page,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# ENRICHMENT ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/enriched/sources")
def get_enriched_sources():
    sources = []
    if os.path.exists(ENRICHMENT_DIR):
        for src_name, info in worker.SOURCE_MAP.items():
            enriched_fn = info["output"].replace("_extracted.json", "_enriched.json")
            filepath = os.path.join(ENRICHMENT_DIR, enriched_fn)
            if os.path.exists(filepath):
                stats = os.stat(filepath)
                sources.append({
                    "id": info["id"],
                    "name": src_name,
                    "file": enriched_fn,
                    "size": stats.st_size,
                    "last_modified": stats.st_mtime
                })
    return sources

@app.get("/api/enriched/data/{source_id}")
def get_enriched_data(source_id: str, page: int = 1, limit: int = 50, search: str = None, ioc_type: str = None, priority: str = None, enrich_source: str = None):
    info = None
    for src_name, src_info in worker.SOURCE_MAP.items():
        if src_info["id"] == source_id:
            info = src_info
            break

    if not info:
        raise HTTPException(status_code=404, detail="Source not found")

    enriched_fn = info["output"].replace("_extracted.json", "_enriched.json")
    filepath = os.path.join(ENRICHMENT_DIR, enriched_fn)

    if not os.path.exists(filepath):
        return {"data": [], "total": 0, "page": page, "limit": limit}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            all_data = json.load(f)

        # 0. Severity / Priority Filtering
        if priority:
            all_data = [d for d in all_data if d.get("priority_score", "").upper() == priority.upper()]

        # 0b. Enrichment Source Filtering
        if enrich_source:
            src = enrich_source.lower()
            if src == "vt":
                all_data = [d for d in all_data if any(
                    (i.get("ioc_enrichment") or {}).get("vt_total_engines", 0) > 0
                    for i in d.get("iocs", [])
                )]
            elif src == "abuseipdb":
                all_data = [d for d in all_data if any(
                    (i.get("ioc_enrichment") or {}).get("abuseConfidenceScore") is not None
                    for i in d.get("iocs", [])
                )]
            elif src == "urlscan":
                all_data = [d for d in all_data if any(
                    (i.get("ioc_enrichment") or {}).get("passer_par_urlscan") == 1
                    for i in d.get("iocs", [])
                )]

        # 1. Type Filtering
        if ioc_type:
            t_low = ioc_type.lower()
            if t_low == "cve":
                all_data = [d for d in all_data if d.get("cves")]
            else:
                all_data = [
                    d for d in all_data 
                    if any(i.get("type", "").lower() == t_low for i in d.get("iocs", []))
                ]

        # 2. Search Filtering
        if search:
            search_low = search.lower()
            all_data = [
                d for d in all_data 
                if search_low in str(d.get("record_id", "")).lower() or 
                   any(search_low in str(t).lower() for t in d.get("tags", [])) or
                   search_low in str(d.get("raw_text", "")).lower()
            ]
            
        total = len(all_data)
        start = (page - 1) * limit
        end = start + limit
        return {
            "data": all_data[start:end],
            "total": total,
            "page": page,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# MITRE ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/mitre/sources")
def get_mitre_sources():
    sources = []
    if os.path.exists(MITRE_DIR):
        for src_name, info in worker.SOURCE_MAP.items():
            mitre_fn = info["output"].replace("_extracted.json", "_mitre.json")
            filepath = os.path.join(MITRE_DIR, mitre_fn)
            if os.path.exists(filepath):
                stats = os.stat(filepath)
                sources.append({
                    "id": info["id"],
                    "name": src_name,
                    "file": mitre_fn,
                    "size": stats.st_size,
                    "last_modified": stats.st_mtime
                })
    return sources

@app.get("/api/mitre/data/{source_id}")
def get_mitre_data(source_id: str, page: int = 1, limit: int = 50, search: str = None, ioc_type: str = None):
    info = None
    for src_name, src_info in worker.SOURCE_MAP.items():
        if src_info["id"] == source_id:
            info = src_info
            break
    
    if not info:
        raise HTTPException(status_code=404, detail="Source not found")
        
    mitre_fn = info["output"].replace("_extracted.json", "_mitre.json")
    filepath = os.path.join(MITRE_DIR, mitre_fn)
    
    if not os.path.exists(filepath):
        return {"data": [], "total": 0, "page": page, "limit": limit}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            all_data = json.load(f)
            
        # Filter for only records that have mitre_attack mapping
        all_data = [d for d in all_data if d.get("mitre_attack")]

        # 1. Type Filtering
        if ioc_type:
            t_low = ioc_type.lower()
            if t_low == "cve":
                all_data = [d for d in all_data if d.get("cves")]
            else:
                all_data = [
                    d for d in all_data 
                    if any(i.get("type", "").lower() == t_low for i in d.get("iocs", []))
                ]

        # 2. Search Filtering
        if search:
            search_low = search.lower()
            all_data = [
                d for d in all_data 
                if search_low in str(d.get("record_id", "")).lower() or 
                   any(search_low in str(t).lower() for t in d.get("tags", [])) or
                   search_low in str(d.get("raw_text", "")).lower()
            ]
            
        total = len(all_data)
        start = (page - 1) * limit
        end = start + limit
        return {
            "data": all_data[start:end],
            "total": total,
            "page": page,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# CORRELATION ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/correlated/data")
def get_correlated_data(page: int = 1, limit: int = 50, search: str = None, priority: str = None):
    try:
        files = [f for f in os.listdir(CORRELATION_DIR) if f.startswith("correlation_file_") and f.endswith(".json")]
        if not files:
            filepath = os.path.join(CORRELATION_DIR, "correlated_events_soc_enriched.json")
        else:
            filepath = max([os.path.join(CORRELATION_DIR, f) for f in files], key=os.path.getmtime)
    except Exception:
        filepath = os.path.join(CORRELATION_DIR, "correlated_events_soc_enriched.json")

    if not os.path.exists(filepath):
        return {"data": [], "total": 0, "page": page, "limit": limit}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            all_data = json.load(f)
            
        # 1. Priority Filtering
        if priority:
            p_low = priority.upper()
            all_data = [d for d in all_data if d.get("priority_score") == p_low]

        # 2. Search Filtering
        if search:
            search_low = search.lower()
            all_data = [
                d for d in all_data 
                if search_low in str(d.get("event_name", "")).lower() or 
                   search_low in str(d.get("group_id", "")).lower() or
                   any(search_low in str(t).lower() for t in d.get("tags", [])) or
                   any(search_low in str(ioc.get("value", "")).lower() for ioc in d.get("iocs", []))
            ]
            
        total = len(all_data)
        start = (page - 1) * limit
        end = start + limit
        return {
            "data": all_data[start:end],
            "total": total,
            "page": page,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mitre/matrix")
def get_mitre_matrix_stats():
    """
    Aggregates technique counts across all MITRE enriched files.
    Returns a dictionary of {technique_id: count}.
    """
    tech_counts = {}
    if os.path.exists(MITRE_DIR):
        for fn in os.listdir(MITRE_DIR):
            if not fn.endswith("_mitre.json"): continue
            filepath = os.path.join(MITRE_DIR, fn)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
                for record in records:
                    mitre = record.get("mitre_attack", [])
                    for entry in mitre:
                        tech_id = entry.get("id")
                        if tech_id and not tech_id.startswith("TA"):
                            tech_counts[tech_id] = tech_counts.get(tech_id, 0) + 1
            except:
                continue
    return tech_counts

@app.get("/api/settings/ai")
def get_ai_settings():
    """Returns current AI provider configuration (keys are masked)."""
    ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
    config = {
        "provider": os.getenv("AI_PROVIDER", "gemini"),
        "gemini_api_key": "",
        "openai_api_key": "",
        "openrouter_api_key": "",
        "openrouter_model": os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001"),
        "ollama_url": os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate"),
        "ollama_model": os.getenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b"),
    }
    # Mask keys: show only last 4 chars
    for key_name, env_var in [("gemini_api_key","GEMINI_API_KEY"),("openai_api_key","OPENAI_API_KEY"),("openrouter_api_key","OPENROUTER_API_KEY")]:
        val = os.getenv(env_var, "")
        config[key_name] = ("*" * (len(val) - 4) + val[-4:]) if len(val) > 4 else ("*" * len(val))
    return config

@app.post("/api/settings/ai")
async def save_ai_settings(body: dict):
    """Saves AI provider configuration to .env file."""
    ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
    
    # Load existing .env content
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
    
    def set_env_var(lines, key, value):
        """Update or append a key=value line."""
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}=") or line.strip().startswith(f"{key} ="):
                lines[i] = f"{key}={value}\n"
                return lines
        lines.append(f"{key}={value}\n")
        return lines

    mapping = {
        "provider": "AI_PROVIDER",
        "openrouter_model": "OPENROUTER_MODEL",
        "ollama_url": "OLLAMA_URL",
        "ollama_model": "OLLAMA_MODEL",
    }
    key_mapping = {
        "gemini_api_key": "GEMINI_API_KEY",
        "openai_api_key": "OPENAI_API_KEY",
        "openrouter_api_key": "OPENROUTER_API_KEY",
    }

    for field, env_var in mapping.items():
        if field in body:
            lines = set_env_var(lines, env_var, body[field])

    for field, env_var in key_mapping.items():
        val = body.get(field, "")
        # Only save if it doesn't look like a masked value (all stars)
        if val and not all(c == '*' for c in val.replace('*', '')):
            if not (val.startswith("*") and "*" in val and len(val) > 4):
                lines = set_env_var(lines, env_var, val)

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Reload env vars in memory
    from dotenv import load_dotenv
    load_dotenv(ENV_PATH, override=True)

    return {"status": "success", "message": "Configuration AI sauvegardée."}

ENRICHMENT_KEYS = [
    ("virustotal_api_key",      "VIRUSTOTAL_API_KEY"),
    ("abuseipdb_api_key",       "ABUSEIPDB_API_KEY"),
    ("urlscan_api_key",         "URLScan_API_KEY"),
    ("nvd_api_key",             "NVD_API_KEY"),
    ("otx_api_key",             "OTX_API_KEY"),
    ("threatfox_api_key",       "THREATFOX_API_KEY"),
    ("urlhaus_api_key",         "URLHAUS_API_KEY"),
    ("malwarebazaar_api_key",   "MALWAREBAZAAR_API_KEY"),
    ("pulsedive_api_key",       "PULSEDIVE_API_KEY"),
]

@app.get("/api/settings/enrichment")
def get_enrichment_settings():
    """Returns current enrichment/source API keys (masked)."""
    config = {}
    for field, env_var in ENRICHMENT_KEYS:
        val = os.getenv(env_var, "")
        config[field] = ("*" * (len(val) - 4) + val[-4:]) if len(val) > 4 else ("*" * len(val))
    return config

@app.post("/api/settings/enrichment")
async def save_enrichment_settings(body: dict):
    """Saves enrichment/source API keys to .env file."""
    ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

    def set_env_var(lines, key, value):
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}=") or line.strip().startswith(f"{key} ="):
                lines[i] = f"{key}={value}\n"
                return lines
        lines.append(f"{key}={value}\n")
        return lines

    for field, env_var in ENRICHMENT_KEYS:
        val = body.get(field, "")
        if val and not (val.startswith("*") and "*" in val and len(val) > 4):
            lines = set_env_var(lines, env_var, val)

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)

    from dotenv import load_dotenv
    load_dotenv(ENV_PATH, override=True)

    return {"status": "success", "message": "Configuration enrichissement sauvegardée."}

@app.get("/api/settings/integrations")
def get_integration_settings():
    """Returns MISP and Telegram configuration (keys masked)."""
    misp_key = os.getenv("MISP_KEY", "")
    return {
        "misp_url":        os.getenv("MISP_URL", ""),
        "misp_key":        ("*" * (len(misp_key) - 4) + misp_key[-4:]) if len(misp_key) > 4 else ("*" * len(misp_key)),
        "misp_verifycert": os.getenv("MISP_VERIFYCERT", "False"),
        "telegram_api_id":   os.getenv("TELEGRAM_API_ID", ""),
        "telegram_api_hash": os.getenv("TELEGRAM_API_HASH", ""),
        "telegram_phone":    os.getenv("TELEGRAM_PHONE", ""),
    }

@app.post("/api/settings/integrations")
async def save_integration_settings(body: dict):
    """Saves MISP and Telegram configuration to .env file."""
    ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

    def set_env_var(lines, key, value):
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}=") or line.strip().startswith(f"{key} ="):
                lines[i] = f"{key}={value}\n"
                return lines
        lines.append(f"{key}={value}\n")
        return lines

    plain_fields = {
        "misp_url":          "MISP_URL",
        "misp_verifycert":   "MISP_VERIFYCERT",
        "telegram_api_id":   "TELEGRAM_API_ID",
        "telegram_api_hash": "TELEGRAM_API_HASH",
        "telegram_phone":    "TELEGRAM_PHONE",
    }
    secret_fields = {
        "misp_key": "MISP_KEY",
    }

    for field, env_var in plain_fields.items():
        if field in body:
            lines = set_env_var(lines, env_var, body[field])

    for field, env_var in secret_fields.items():
        val = body.get(field, "")
        if val and not (val.startswith("*") and "*" in val and len(val) > 4):
            lines = set_env_var(lines, env_var, val)

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)

    from dotenv import load_dotenv
    load_dotenv(ENV_PATH, override=True)

    return {"status": "success", "message": "Configuration intégrations sauvegardée."}

# ──────────────────────────────────────────────────────────────────────────────
# SCHEDULER ENDPOINTS (MULTIPLE)
# ──────────────────────────────────────────────────────────────────────────────

SCHEDULES_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "schedules.json"))
schedules_db = {}
# Format: { "id": { "id", "source_name", "step_name", "interval_minutes", "active", "next_run", "task" } }

def load_schedules():
    global schedules_db
    if os.path.exists(SCHEDULES_FILE):
        try:
            with open(SCHEDULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for sid, j in data.items():
                schedules_db[sid] = {
                    "id": j["id"],
                    "source_name": j["source_name"],
                    "step_name": j["step_name"],
                    "interval_minutes": j["interval_minutes"],
                    "active": j["active"],
                    # Au démarrage, le "next_run" est calculé à partir de maintenant + interval, comme demandé
                    "next_run": datetime.now() + timedelta(minutes=j["interval_minutes"]) if j["active"] else None,
                    "task": None
                }
        except Exception as e:
            logger.error(f"Error loading schedules: {e}")

def save_schedules():
    data = {}
    for sid, j in schedules_db.items():
        data[sid] = {
            "id": j["id"],
            "source_name": j["source_name"],
            "step_name": j["step_name"],
            "interval_minutes": j["interval_minutes"],
            "active": j["active"]
        }
    try:
        with open(SCHEDULES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving schedules: {e}")

@app.on_event("startup")
async def startup_event():
    load_schedules()
    for sid, job in schedules_db.items():
        if job["active"]:
            job["task"] = asyncio.create_task(scheduler_job_loop(sid))
# Format: { "id": { "id", "source_name", "step_name", "interval_minutes", "active", "next_run", "task" } }

async def scheduler_job_loop(schedule_id: str):
    while True:
        job = schedules_db.get(schedule_id)
        if not job or not job.get("active"):
            break

        now = datetime.now()
        if job.get("next_run") and now >= job["next_run"]:
            # Trigger run
            external_id = str(uuid.uuid4())
            source_name = job.get("source_name", "Unified Extraction")
            step_name = job.get("step_name", "Pipeline Complet")

            new_run = {
                "run_id": external_id,
                "source_name": source_name,
                "source_type": "Scheduled",
                "status_global": "running"
            }
            db.create_run(new_run)
            
            if step_name == "Pipeline Complet":
                steps = [
                    "Collecte", "Extraction CVE / IOC", "AbuseIPDB Enrichment", 
                    "VirusTotal Enrichment", "Geolocalisation", "URLScan", 
                    "Enrichissement CVE", "Classification", "MITRE Mapping", 
                    "Corrélation SOC", "Export STIX", "Intégration MISP"
                ]
                for s in steps:
                    db.update_step(external_id, {
                        "step_name": s, "status": "pending",
                        "ioc_count": 0, "cve_count": 0, "logs": [],
                    })
                asyncio.create_task(worker.execute_pipeline_task(external_id, source_name))
            else:
                db.update_step(external_id, {
                    "step_name": step_name, "status": "pending",
                    "ioc_count": 0, "cve_count": 0, "logs": [],
                })
                asyncio.create_task(worker.execute_targeted_task(external_id, source_name, step_name))

            # Reschedule
            job["next_run"] = datetime.now() + timedelta(minutes=job["interval_minutes"])
        
        await asyncio.sleep(10)

from pydantic import BaseModel
from typing import Optional

class ScheduleCreateRequest(BaseModel):
    source_name: str
    step_name: str
    interval_minutes: int

class ScheduleUpdateRequest(BaseModel):
    action: str
    interval_minutes: Optional[int] = None

@app.get("/api/schedules")
def get_schedules():
    res = []
    for sid, job in schedules_db.items():
        res.append({
            "id": sid,
            "source_name": job.get("source_name"),
            "step_name": job.get("step_name"),
            "interval_minutes": job.get("interval_minutes"),
            "active": job.get("active"),
            "next_run": job.get("next_run").isoformat() if job.get("next_run") else None
        })
    return res

@app.post("/api/schedules")
async def create_schedule(req: ScheduleCreateRequest):
    sid = str(uuid.uuid4())
    schedules_db[sid] = {
        "id": sid,
        "source_name": req.source_name,
        "step_name": req.step_name,
        "interval_minutes": req.interval_minutes,
        "active": True,
        "next_run": datetime.now(),
        "task": None
    }
    schedules_db[sid]["task"] = asyncio.create_task(scheduler_job_loop(sid))
    save_schedules()
    return {"status": "success", "id": sid, "message": "Planification créée et démarrée"}

@app.put("/api/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, req: ScheduleUpdateRequest):
    job = schedules_db.get(schedule_id)
    if not job:
        raise HTTPException(status_code=404, detail="Planification non trouvée")
    
    if req.action == "start":
        if req.interval_minutes:
            job["interval_minutes"] = req.interval_minutes
        job["active"] = True
        job["next_run"] = datetime.now()
        if job["task"] is None or job["task"].done():
            job["task"] = asyncio.create_task(scheduler_job_loop(schedule_id))
        save_schedules()
        return {"status": "success", "message": "Planification démarrée"}
    
    elif req.action == "stop":
        job["active"] = False
        job["next_run"] = None
        if job["task"] and not job["task"].done():
            job["task"].cancel()
        job["task"] = None
        save_schedules()
        return {"status": "success", "message": "Planification arrêtée"}
    
    raise HTTPException(status_code=400, detail="Action invalide")

@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    job = schedules_db.get(schedule_id)
    if not job:
        raise HTTPException(status_code=404, detail="Planification non trouvée")
    
    job["active"] = False
    if job["task"] and not job["task"].done():
        job["task"].cancel()
    del schedules_db[schedule_id]
    save_schedules()
    return {"status": "success", "message": "Planification supprimée"}

# Keep legacy endpoint for compatibility with Dashboard.jsx if needed (until updated)
@app.get("/api/schedule/status")
def get_schedule_status_legacy():
    # Return first active schedule or default
    active = next((j for j in schedules_db.values() if j["active"]), None)
    if active:
        return {
            "active": True,
            "interval_minutes": active["interval_minutes"],
            "next_run": active["next_run"].isoformat() if active.get("next_run") else None
        }
    return {"active": False, "interval_minutes": 60, "next_run": None}

@app.post("/api/schedule")
async def manage_schedule_legacy(req: ScheduleUpdateRequest):
    # Backward compatibility
    if req.action == "start":
        sid = "legacy_global"
        if sid not in schedules_db:
            schedules_db[sid] = {
                "id": sid, "source_name": "Unified Extraction", "step_name": "Pipeline Complet",
                "interval_minutes": req.interval_minutes or 60, "active": True, "next_run": datetime.now(), "task": None
            }
        else:
            schedules_db[sid]["interval_minutes"] = req.interval_minutes or 60
            schedules_db[sid]["active"] = True
            schedules_db[sid]["next_run"] = datetime.now()
        
        if schedules_db[sid]["task"] is None or schedules_db[sid]["task"].done():
            schedules_db[sid]["task"] = asyncio.create_task(scheduler_job_loop(sid))
        save_schedules()
        return {"status": "success"}
    elif req.action == "stop":
        sid = "legacy_global"
        if sid in schedules_db:
            schedules_db[sid]["active"] = False
            schedules_db[sid]["next_run"] = None
            if schedules_db[sid]["task"] and not schedules_db[sid]["task"].done():
                schedules_db[sid]["task"].cancel()
            save_schedules()
        return {"status": "success"}

@app.delete("/runs/{run_id}")
def delete_run(run_id: int):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    # Prevent deleting a run that is currently running
    if run.get("status_global") == "running":
        raise HTTPException(status_code=400, detail="Impossible de supprimer un run en cours d'exécution")
    deleted = db.delete_run(run_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"status": "success", "message": "Run supprimé"}

@app.delete("/runs")
def clear_runs():
    db.clear_runs()
    return {"status": "success"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websockets.manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        websockets.manager.disconnect(websocket)
    except:
        websockets.manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    # En lançant uvicorn via ce script, on garantit que la loop policy est fixée avant.
    # Restreindre le rechargement au dossier 'backend' uniquement. 
    # Sinon, uvicorn surveille tout le projet et redémarre l'app quand le pipeline génère des fichiers.
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True, loop="asyncio", reload_dirs=[backend_dir])
# ─── API STIX ────────────────────────────────────────────────────────
@app.get("/api/stix/data")
async def get_stix_data():
    """
    Retourne le contenu du bundle STIX exporté.
    """
    out_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation")
    try:
        files = [f for f in os.listdir(out_dir) if f.startswith("stix_export_") and f.endswith(".json")]
        if not files:
            stix_path = os.path.join(out_dir, "stix_export.json")
        else:
            stix_path = max([os.path.join(out_dir, f) for f in files], key=os.path.getmtime)
    except Exception:
        stix_path = os.path.join(out_dir, "stix_export.json")

    if not os.path.exists(stix_path):
        return {"objects": [], "type": "bundle"}
    try:
        with open(stix_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-stix-bulletin")
def generate_stix_bulletin():
    try:
        from misp_integration.stix_reporter import STIXReporter
        reporter = STIXReporter()
        pdf_path = reporter.generate_pdf()
        if pdf_path:
            return {"status": "success", "file": os.path.basename(pdf_path), "url": f"/bulletins/{os.path.basename(pdf_path)}"}
        else:
            return {"status": "error", "message": "Échec de la génération du PDF"}
    except Exception as e:
        print(f"[ERROR] Bulletin generation failed: {e}")
        return {"status": "error", "message": str(e)}
