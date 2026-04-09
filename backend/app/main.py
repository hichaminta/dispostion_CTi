import asyncio
import json
import os
import sys
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
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

app = FastAPI(title="CTI Pipeline Tracker API")

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
    steps = ["Collecte", "Extraction CVE / IOC", "Normalisation", "Int\u00e9gration MISP"]
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

@app.get("/stats")
def get_stats():
    from datetime import datetime as dt
    total_ioc = 0
    total_cve = 0
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
