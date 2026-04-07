import os
import sys
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')

# ── Global State ─────────────────────────────────────────────────────────────
# tracks: { "Source Name": { "proc": Popen, "status": "running"|"success"|"error", "pid": 123 } }
active_processes = {}
# tracks: { "Source Name": { "exit_code": 0, "finished_at": "ISO" } }
last_run_status = {}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
SOURCES_DIR = os.path.join(PROJECT_ROOT, "Sources_data")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(BASE_DIR, "extraction.log")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")

# Ensure directories and files
os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, 'w', encoding='utf-8').close()

# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_log_path(source_name):
    """Return sanitized log path for a specific source."""
    if not source_name or source_name == "Global":
        return LOG_FILE
    sanitized = "".join([c if c.isalnum() else "_" for c in source_name])
    return os.path.join(LOGS_DIR, f"{sanitized}.log")

def _get_script_path(source_name):
    """Dynamically return the script path for a source (matches source name to directory name)."""
    if not source_name:
        return os.path.join(BASE_DIR, "run_all_extractions.py")
    
    # Standard: check for script.py in the source directory
    potential = os.path.join(SOURCES_DIR, source_name, "script.py")
    if os.path.exists(potential):
        return potential
    
    # Fallback/Custom logic could be added here if needed
    return None

def _watch_process(source_name, proc, log_handle):
    """Wait for process to finish and update status."""
    proc.wait()
    try:
        log_handle.close()
    except:
        pass
    
    exit_code = proc.returncode
    status = "success" if exit_code == 0 else "error"
    
    print(f"[Watch] {source_name} fini (Code: {exit_code}, Status: {status})")
    
    last_run_status[source_name] = {
        "status": status,
        "exit_code": exit_code,
        "finished_at": datetime.now(timezone.utc).isoformat()
    }
    
    if source_name in active_processes:
        del active_processes[source_name]
        
    # Refresh global status.json
    try:
        subprocess.run([sys.executable, "monitor.py"], cwd=BASE_DIR, 
                       capture_output=True, timeout=30)
    except:
        pass

# ── Endpoints ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/status')
def get_status():
    data = {"sources": []}
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except:
            pass
    
    # Inject real-time running/error state
    for s in data.get("sources", []):
        name = s.get("name")
        if name in active_processes:
            s["run_state"] = "running"
        elif name in last_run_status:
            s["run_state"] = last_run_status[name]["status"]
            s["exit_code"] = last_run_status[name]["exit_code"]
        else:
            s["run_state"] = "idle"
            
    return jsonify(data)

@app.route('/api/run', methods=['POST'])
def run_script():
    source_name = request.args.get('source')
    
    # 1. Full pipeline or single source?
    if not source_name:
        cmd = [sys.executable, "run_all_extractions.py"]
        label = "Full Pipeline"
    else:
        script_path = _get_script_path(source_name)
        if not script_path:
            return jsonify({"error": f"Source unknown: {source_name}"}), 400
        cmd = [sys.executable, script_path]
        label = source_name

    # Check if already running
    if (source_name or "Global") in active_processes:
        return jsonify({"error": "Déjà en cours"}), 400

    try:
        log_path = _get_log_path(source_name)
        log_handle = open(log_path, 'a', encoding='utf-8')
        log_handle.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] === Lancement : {label} ===\n")
        log_handle.flush()
        
        # Cross-platform handle (Windows CREATE_NO_WINDOW if on windows)
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW
            
        proc = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=log_handle,
            cwd=os.path.dirname(script_path) if source_name else BASE_DIR,
            creationflags=creationflags
        )
        
        # Track the process
        track_name = source_name or "Global"
        active_processes[track_name] = {"proc": proc, "pid": proc.pid}
            
        threading.Thread(target=_watch_process, args=(track_name, proc, log_handle), daemon=True).start()
        
        return jsonify({"status": "launched", "pid": proc.pid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run/stage', methods=['POST'])
def run_pipeline_stage():
    stage_id = request.args.get('stage')
    if not stage_id:
        return jsonify({"error": "Stage ID manquant"}), 400

    # Mapping stage IDs to scripts
    # Note: Many scripts are in the parent directory of the platform folder
    stage_scripts = {
        "collecte": os.path.join(BASE_DIR, "run_all_extractions.py"),
        "extraction-norm": os.path.join(PROJECT_ROOT, "run_adapters.py"), # We'll start with this
        "enrichissement": os.path.join(PROJECT_ROOT, "run_enrichment.py"),
        "structuration": os.path.join(PROJECT_ROOT, "run_structuration.py"),
        "misp": os.path.join(PROJECT_ROOT, "run_misp.py")
    }

    if stage_id not in stage_scripts:
        return jsonify({"error": f"Stage inconnu: {stage_id}"}), 400

    script_path = stage_scripts[stage_id]
    
    # Check if already running
    track_name = f"Stage_{stage_id}"
    if track_name in active_processes:
        return jsonify({"error": "Cette étape est déjà en cours d'exécution"}), 400

    try:
        log_path = _get_log_path(track_name)
        log_handle = open(log_path, 'a', encoding='utf-8')
        log_handle.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] === Lancement Étape : {stage_id} ===\n")
        log_handle.flush()
        
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW
            
        proc = subprocess.Popen(
            [sys.executable, script_path],
            stdout=log_handle,
            stderr=log_handle,
            cwd=PROJECT_ROOT if stage_id != "collecte" else BASE_DIR,
            creationflags=creationflags
        )
        
        active_processes[track_name] = {"proc": proc, "pid": proc.pid}
        threading.Thread(target=_watch_process, args=(track_name, proc, log_handle), daemon=True).start()
        
        return jsonify({"status": "launched", "pid": proc.pid, "stage": stage_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_script():
    source_name = request.args.get('source')
    if not source_name or source_name not in active_processes:
        return jsonify({"error": "Non trouvé ou non actif"}), 404
    
    try:
        proc_info = active_processes[source_name]
        proc_info["proc"].terminate() # Graceful shutdown
        return jsonify({"status": "terminated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
def get_logs():
    source_name = request.args.get('source')
    log_path = _get_log_path(source_name)
    lines_count = int(request.args.get('lines', 100))
    log_filter = request.args.get('filter') # 'errors' | 'success'
    
    try:
        if not os.path.exists(log_path):
             return jsonify({"lines": [], "running": len(active_processes) > 0})
             
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
            # Application du filtre ligne par ligne
            if log_filter == 'errors':
                keywords = ["error", "fail", "erreur", "échec", "exception", "critical", "❌"]
                lines = [L for L in lines if any(k in L.lower() for k in keywords)]
            elif log_filter == 'success':
                keywords = ["success", "réussite", "terminé", "fini", "ajouté", "✔", "✓"]
                lines = [L for L in lines if any(k in L.lower() for k in keywords)]

            # Return last N lines
            return jsonify({
                "lines": lines[-lines_count:] if lines else [],
                "source": source_name or "Global",
                "filter": log_filter,
                "running": (source_name in active_processes) if source_name else (len(active_processes) > 0)
            })
    except Exception as e:
        print(f"[Error] Log reading failed for {source_name}: {e}")
        return jsonify({"lines": [], "running": False, "error": str(e)})

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    source_name = request.args.get('source')
    log_path = _get_log_path(source_name)
    try:
        target = source_name or "Globale"
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"--- Console {target} vidée à {datetime.now().strftime('%H:%M:%S')} ---\n")
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
def refresh_status_endpoint():
    """Manual trigger for monitor.py"""
    try:
        subprocess.run([sys.executable, "monitor.py"], cwd=BASE_DIR, 
                       capture_output=True, timeout=60, check=True)
        return jsonify({"status": "refreshed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data')
def get_data():
    source_name = request.args.get('source')
    if not source_name: return jsonify({"error": "Paramètre source manquant"}), 400

    # 1. Look up data file name from status.json
    filename = None
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                status_data = json.load(f)
                source_info = next((s for s in status_data.get("sources", []) if s["name"] == source_name), None)
                if source_info:
                    filename = source_info.get("data_file")
        except Exception as e:
            print(f"[Data] Error reading status.json: {e}")

    # 2. Locate the file in the source folder
    potential_path = None
    if filename:
        p = os.path.join(SOURCES_DIR, source_name, filename)
        if os.path.exists(p):
            potential_path = p

    # 3. Fallback search (find any large JSON in that folder)
    if not potential_path:
        source_dir = os.path.join(SOURCES_DIR, source_name)
        if os.path.exists(source_dir) and os.path.isdir(source_dir):
            for f in os.listdir(source_dir):
                if f.endswith('.json') and 'tracking' not in f and 'format' not in f:
                    potential_path = os.path.join(source_dir, f)
                    break
    
    if not potential_path: return jsonify({"error": "Données introuvables"}), 404
    
    try:
        # Load only first 1000 records for performance
        with open(potential_path, 'r', encoding='utf-8', errors='replace') as f:
            full_data = json.load(f)
            return jsonify(full_data[:1000] if isinstance(full_data, list) else full_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Auto-open browser
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        print("\n" + "="*60)
        print("  CTI Pipeline Platform (Flask) — Serveur Démarré")
        print("  Accès : http://localhost:5000")
        print("="*60 + "\n")
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open("http://localhost:5000")).start()
    
    app.run(port=5000, debug=True)
