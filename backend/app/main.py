import asyncio
import json
import os
import sys
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

from . import schemas, database, websockets, worker
from .database import db

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_cve_ioc"))
ENRICHMENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output_enrichment"))
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dashboard"))

app = FastAPI(title="CTI Pipeline Tracker API")

app.mount("/results", StaticFiles(directory=DASHBOARD_DIR, html=True), name="results")

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
    steps = ["Collecte", "Extraction CVE / IOC", "NLP Enrichment", "Geolocalisation", "URLScan", "Normalisation"]
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
    from datetime import datetime as dt
    total_ioc = 0
    total_cve = 0
    # Process both standard and enriched (standardized has correct full count)
    if os.path.exists(OUTPUT_DIR):
        for fn in os.listdir(OUTPUT_DIR):
            if not fn.endswith(".json"): continue
            filepath = os.path.join(OUTPUT_DIR, fn)
            is_cve_only = "nvd" in fn.lower()
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for rec in data:
                        if isinstance(rec, dict):
                            if not is_cve_only: total_ioc += len(rec.get("iocs", []) or [])
                            total_cve += len(rec.get("cves", []) or [])
                elif isinstance(data, dict):
                    if not is_cve_only: total_ioc += len(data.get("iocs", []) or [])
                    total_cve += len(data.get("cves", []) or [])
            except: pass
    runs = db.get_runs()
    durations = []
    for r in runs:
        ca, ua = r.get("created_at"), r.get("updated_at")
        if ca and ua:
            try:
                d = (dt.fromisoformat(ua) - dt.fromisoformat(ca)).total_seconds()
                if d > 0: durations.append(d)
            except: pass
    res = {
        "total_ioc": total_ioc,
        "total_cve": total_cve,
        "total_runs": len(runs),
        "success_runs": sum(1 for r in runs if r.get("status_global") == "success"),
        "running_runs": sum(1 for r in runs if r.get("status_global") == "running"),
        "avg_duration_sec": round(sum(durations) / len(durations)) if durations else 0,
    }
    return res

@app.get("/api/stats/countries")
def get_country_stats():
    country_counts = {}
    if os.path.exists(ENRICHMENT_DIR):
        for fn in os.listdir(ENRICHMENT_DIR):
            if not fn.endswith("_enriched.json"): continue
            filepath = os.path.join(ENRICHMENT_DIR, fn)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
                for record in records:
                    # Get unique countries for this specific record to avoid over-counting duplicate tags
                    record_countries = set()
                    
                    # 1. From IOCs (IOC-centric model)
                    for ioc in record.get("iocs", []):
                        geos = ioc.get("ioc_enrichment", {}).get("geography", [])
                        for g in geos: record_countries.add(g)
                    
                    # 2. From NLP Advanced (Legacy/Generic extraction)
                    geos_adv = record.get("enrichment", {}).get("nlp_advanced", {}).get("geography", [])
                    for g in geos_adv: record_countries.add(g)
                    
                    # 3. From record tags (Fallback)
                    for tag in record.get("tags", []):
                        # Simple heuristic: if it's a known country or matches our geo list
                        # (We'll count everything in record_countries set for now)
                        pass
                    
                    for country in record_countries:
                        if country and len(country) > 1: # Avoid junk
                            country_counts[country] = country_counts.get(country, 0) + 1
            except:
                continue
    
    # Sort and take top 10
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"country": c, "count": n} for c, n in sorted_countries[:12]]

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
