import asyncio
import json
import os
import sys
import time
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from typing import List
import uuid

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

from datetime import datetime
from . import schemas, database, websockets, worker, leaks_router
from .database import db

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_cve_ioc"))
ENRICHMENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_enrichment"))
MITRE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation")) # Use correlation output for some stats too
CORRELATION_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation"))
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dashboard"))

app = FastAPI(title="CTI Pipeline Tracker API")
app.include_router(leaks_router.router)

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
    steps = ["Collecte", "Extraction CVE / IOC", "Geolocalisation", "URLScan", "Enrichissement CVE", "Classification", "MITRE Mapping", "Corrélation SOC", "Export STIX", "Intégration MISP"]
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
    
    # Initialize only the specified step and get the updated run object
    run_obj = db.update_step(external_id, {
        "step_name": step_name,
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
def get_enriched_data(source_id: str, page: int = 1, limit: int = 50, search: str = None, ioc_type: str = None):
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
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True, loop="asyncio")
# ─── API STIX ────────────────────────────────────────────────────────
@app.get("/api/stix/data")
async def get_stix_data():
    """
    Retourne le contenu du bundle STIX exporté.
    """
    stix_path = os.path.join(os.path.dirname(__file__), "..", "..", "output_correlation", "stix_export.json")
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
