import http.server
import socketserver
import webbrowser
import os
import threading
import subprocess
import sys
import time
import json

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

SOURCES_DIR = os.path.join(os.path.dirname(DIRECTORY), "Sources_data")
LOG_FILE = os.path.join(DIRECTORY, "pipeline_run.log")

# Track running processes
running_processes = []
pipeline_running = False

def cleanup_processes():
    """Clean up finished processes from the tracking list."""
    global pipeline_running, running_processes
    running_processes = [p for p in running_processes if p.poll() is None]
    if not running_processes:
        pipeline_running = False

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def _send_json(self, data, status=200):
        """Helper to send a JSON response."""
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(self.path)

        # ---- API: Get paginated data from a source ----
        if parsed_url.path == '/api/data':
            params = parse_qs(parsed_url.query)
            source_name = params.get('source', [None])[0]
            page = int(params.get('page', [1])[0])
            per_page = int(params.get('per_page', [50])[0])
            per_page = min(per_page, 100)  # cap

            if not source_name:
                return self._send_json({"error": "Parameter 'source' is required"}, 400)

            data_file = self._find_data_file(source_name)
            if not data_file:
                return self._send_json({"error": f"Source '{source_name}' not found"}, 404)

            try:
                with open(data_file, 'r', encoding='utf-8') as f:
                    all_data = json.load(f)

                if not isinstance(all_data, list):
                    return self._send_json({"error": "Data format not supported"}, 500)

                total = len(all_data)
                total_pages = max(1, (total + per_page - 1) // per_page)
                page = max(1, min(page, total_pages))

                start = (page - 1) * per_page
                end = start + per_page
                page_data = all_data[start:end]

                columns = list(page_data[0].keys()) if page_data else []

                return self._send_json({
                    "source": source_name,
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "total_pages": total_pages,
                    "columns": columns,
                    "data": page_data
                })

            except Exception as e:
                print(f"Error reading data for {source_name}: {e}")
                return self._send_json({"error": str(e)}, 500)

        # ---- API: Get live logs ----
        elif parsed_url.path == '/api/logs':
            params = parse_qs(parsed_url.query)
            max_lines = int(params.get('lines', [200])[0])
            
            cleanup_processes()
            
            lines = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                        all_lines = f.readlines()
                        lines = all_lines[-max_lines:]
                except Exception:
                    lines = []
            
            return self._send_json({
                "lines": [l.rstrip('\n\r') for l in lines],
                "running": pipeline_running,
                "process_count": len(running_processes)
            })

        # ---- Default: serve static files ----
        return super().do_GET()

    def _find_data_file(self, source_name):
        """Find the data file path for a given source from status.json."""
        status_path = os.path.join(DIRECTORY, "status.json")
        try:
            with open(status_path, 'r', encoding='utf-8') as f:
                status = json.load(f)
            for src in status.get("sources", []):
                if src["name"] == source_name:
                    data_filename = src.get("data_file")
                    if data_filename:
                        data_path = os.path.join(SOURCES_DIR, source_name, data_filename)
                        if os.path.exists(data_path):
                            return data_path
        except Exception:
            pass
        
        source_dir = os.path.join(SOURCES_DIR, source_name)
        if os.path.isdir(source_dir):
            for f in os.listdir(source_dir):
                if f.endswith('_data.json') or f.endswith('_full.json') or f.endswith('_iocs.json') or f.endswith('_pulses.json'):
                    return os.path.join(source_dir, f)
        return None

    def do_POST(self):
        from urllib.parse import urlparse, parse_qs
        global pipeline_running, running_processes
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/run':
            params = parse_qs(parsed_url.query)
            source_name = params.get('source', [None])[0]
            
            try:
                # Clear the log file for a fresh run
                with open(LOG_FILE, 'w', encoding='utf-8') as f:
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    if source_name:
                        f.write(f"[{timestamp}] === Lancement de l'extraction : {source_name} ===\n\n")
                    else:
                        f.write(f"[{timestamp}] === Lancement du Pipeline complet ===\n\n")
                
                log_handle = open(LOG_FILE, 'a', encoding='utf-8', errors='replace')
                
                if source_name:
                    print(f"\n>>> Commande reçue : Lancement de la source [{source_name}]")
                    script_path = os.path.join(SOURCES_DIR, source_name, "script.py")
                    if os.path.exists(script_path):
                        proc = subprocess.Popen(
                            [sys.executable, "-u", "script.py"],
                            cwd=os.path.dirname(script_path),
                            stdout=log_handle,
                            stderr=subprocess.STDOUT
                        )
                        running_processes.append(proc)
                    else:
                        raise Exception(f"Script introuvable pour {source_name}")
                else:
                    print("\n>>> Commande reçue : Lancement du Pipeline complet...")
                    runner_path = os.path.join(os.path.dirname(DIRECTORY), "run_all_extractions.py")
                    proc = subprocess.Popen(
                        [sys.executable, "-u", runner_path],
                        stdout=log_handle,
                        stderr=subprocess.STDOUT
                    )
                    running_processes.append(proc)
                
                pipeline_running = True
                
                # Schedule status refreshes
                threading.Timer(10, run_monitor_silent).start()
                threading.Timer(30, run_monitor_silent).start()
                
                self._send_json({"status": "started"})
            except Exception as e:
                print(f"Erreur lors du lancement : {e}")
                self._send_json({"error": str(e)}, 500)

        elif parsed_url.path == '/api/refresh':
            try:
                run_monitor_silent()
                self._send_json({"status": "refreshed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        elif parsed_url.path == '/api/logs/clear':
            try:
                with open(LOG_FILE, 'w', encoding='utf-8') as f:
                    f.write("")
                self._send_json({"status": "cleared"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()

def run_monitor_silent():
    """Run monitor.py silently to update status.json."""
    try:
        subprocess.run(
            [sys.executable, os.path.join(DIRECTORY, "monitor.py")],
            check=True,
            capture_output=True
        )
        print(f"[Auto-Refresh] status.json mis à jour à {time.strftime('%H:%M:%S')}")
    except Exception as e:
        print(f"[Auto-Refresh] Erreur : {e}")

def run_monitor():
    """Exécute le moniteur pour mettre à jour status.json (visible dans la console)."""
    print("Mise à jour des statistiques du pipeline...")
    try:
        subprocess.run([sys.executable, os.path.join(DIRECTORY, "monitor.py")], check=True)
        print("Statistiques mises à jour avec succès.")
    except Exception as e:
        print(f"Erreur lors de la mise à jour : {e}")

def auto_refresh_loop(interval=60):
    """Background thread that refreshes status.json periodically."""
    while True:
        time.sleep(interval)
        run_monitor_silent()

def start_server():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serveur lancé sur http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    # 1. Mettre à jour les données initiales
    run_monitor()
    
    # 2. Lancer le thread de rafraîchissement automatique (toutes les 60s)
    refresh_thread = threading.Thread(name='auto_refresh', target=auto_refresh_loop, args=(60,), daemon=True)
    refresh_thread.start()
    print("Auto-refresh activé : status.json sera mis à jour toutes les 60 secondes.")
    
    # 3. Lancer le serveur dans un thread séparé
    daemon = threading.Thread(name='daemon_server', target=start_server, daemon=True)
    daemon.start()
    
    # 4. Ouvrir le navigateur
    print(f"Ouverture du tableau de bord sur http://localhost:{PORT}...")
    time.sleep(1)
    webbrowser.open(f"http://localhost:{PORT}")
    
    # Garder le script en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
        sys.exit(0)

