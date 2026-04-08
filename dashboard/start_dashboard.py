import http.server
import socketserver
import webbrowser
import os, sys, json, urllib.parse, subprocess, threading, uuid, time

PORT = 8000
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_cve_ioc")
EXTRACTORS_DIR = os.path.join(BASE_DIR, "extraction_ioc_cve")
TRACKING_DIR = os.path.join(BASE_DIR, "extraction_ioc_cve", "tracking")
MAX_RECORDS = 1000  # max par source pour éviter crash navigateur
PREVIEW_RECORDS = 50  # records for the source sub-dashboard preview

SOURCES = [
    'abuseipdb','alienvault','cins_army','feodotracker',
    'malwarebazaar','nvd','openphish','phishtank',
    'pulsedive','threatfox','urlhaus','virustotal'
]

# ── Job tracker for script execution ──────────────────────────
# { job_id: { 'source': str, 'status': 'running'|'done'|'error', 'lines': [...], 'started': float, 'ended': float } }
_JOBS = {}
_JOBS_LOCK = threading.Lock()

def _run_job(job_id, source, extra_args=None):
    script_path = os.path.join(EXTRACTORS_DIR, f'{source}_extractor.py')
    with _JOBS_LOCK:
        _JOBS[job_id]['status'] = 'running'
        _JOBS[job_id]['started'] = time.time()
    try:
        cmd = [sys.executable, script_path]
        if extra_args:
            cmd.extend(extra_args)
            
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=BASE_DIR, text=True, encoding='utf-8', errors='replace'
        )
        for line in proc.stdout:
            with _JOBS_LOCK:
                _JOBS[job_id]['lines'].append(line.rstrip())
        proc.wait()
        with _JOBS_LOCK:
            _JOBS[job_id]['status'] = 'done' if proc.returncode == 0 else 'error'
            _JOBS[job_id]['returncode'] = proc.returncode
    except Exception as e:
        with _JOBS_LOCK:
            _JOBS[job_id]['lines'].append(f'[SERVER ERROR] {e}')
            _JOBS[job_id]['status'] = 'error'
    with _JOBS_LOCK:
        _JOBS[job_id]['ended'] = time.time()

class CTIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ── API: liste des sources ──────────────────────────────
        if path == '/api/sources':
            result = []
            for s in SOURCES:
                fpath = os.path.join(OUTPUT_DIR, f'{s}_extracted.json')
                tpath = os.path.join(TRACKING_DIR, f'{s}_tracking.json')
                size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
                tracking = {}
                if os.path.exists(tpath):
                    try: tracking = json.load(open(tpath, encoding='utf-8'))
                    except: pass
                result.append({'name': s, 'size_bytes': size, 'tracking': tracking})
            self._json(result)
            return

        # ── API: données d'une source (limitées à MAX_RECORDS) ──
        if path.startswith('/api/source/'):
            source = path[len('/api/source/'):]
            if source not in SOURCES:
                self.send_response(404); self.end_headers(); return
            fpath = os.path.join(OUTPUT_DIR, f'{source}_extracted.json')
            if not os.path.exists(fpath):
                self._json([]); return
            try:
                qs = urllib.parse.parse_qs(parsed.query)
                offset = int(qs.get('offset', ['0'])[0])
                limit  = min(int(qs.get('limit', [str(MAX_RECORDS)])[0]), MAX_RECORDS)
                data = json.load(open(fpath, encoding='utf-8'))
                total = len(data)
                slice_ = data[offset:offset+limit]
                self._json({'total': total, 'offset': offset, 'limit': limit, 'data': slice_})
            except Exception as e:
                self._json({'error': str(e), 'data': []})
            return

        # ── API: preview (PREVIEW_RECORDS échantillonnés) ─────────
        if path.startswith('/api/preview/'):
            source = path[len('/api/preview/'):]
            if source not in SOURCES:
                self.send_response(404); self.end_headers(); return
            fpath = os.path.join(OUTPUT_DIR, f'{source}_extracted.json')
            tpath = os.path.join(TRACKING_DIR, f'{source}_tracking.json')
            tracking = {}
            if os.path.exists(tpath):
                try: tracking = json.load(open(tpath, encoding='utf-8'))
                except: pass
            if not os.path.exists(fpath):
                self._json({'total': 0, 'preview': [], 'tracking': tracking, 'size_bytes': 0})
                return
            try:
                size = os.path.getsize(fpath)
                data = json.load(open(fpath, encoding='utf-8'))
                total = len(data)
                # sample: first 25 + last 25
                if total <= PREVIEW_RECORDS:
                    preview = data
                else:
                    half = PREVIEW_RECORDS // 2
                    preview = data[:half] + data[total-half:]
                self._json({'total': total, 'preview': preview, 'tracking': tracking, 'size_bytes': size})
            except Exception as e:
                self._json({'total': 0, 'preview': [], 'error': str(e), 'tracking': tracking, 'size_bytes': 0})
            return

        # ── API: lancer un script d'extraction ────────────────────
        if path.startswith('/api/run-script/'):
            source = path[len('/api/run-script/'):]
            if source not in SOURCES:
                self.send_response(404); self.end_headers(); return
            
            # Handle parameters
            qs = urllib.parse.parse_qs(parsed.query)
            mode = qs.get('mode', [None])[0]
            extra_args = []
            if mode == 'full':
                extra_args.append('--full')

            job_id = str(uuid.uuid4())[:8]
            with _JOBS_LOCK:
                _JOBS[job_id] = {'source': source, 'status': 'pending', 'lines': [], 'started': None, 'ended': None}
            t = threading.Thread(target=_run_job, args=(job_id, source, extra_args), daemon=True)
            t.start()
            self._json({'job_id': job_id, 'source': source, 'status': 'pending'})
            return

        # Legacy endpoint for compatibility
        if path.startswith('/api/run/'):
            source = path[len('/api/run/'):]
            if source not in SOURCES:
                self.send_response(404); self.end_headers(); return
            job_id = str(uuid.uuid4())[:8]
            with _JOBS_LOCK:
                _JOBS[job_id] = {'source': source, 'status': 'pending', 'lines': [], 'started': None, 'ended': None}
            # No extra args for legacy endpoint
            t = threading.Thread(target=_run_job, args=(job_id, source), daemon=True)
            t.start()
            self._json({'job_id': job_id, 'source': source, 'status': 'pending'})
            return

        # ── API: statut d'un job ───────────────────────────────────
        if path.startswith('/api/job/'):
            job_id = path[len('/api/job/'):]
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
            if not job:
                self.send_response(404); self.end_headers(); return
            self._json(job)
            return

        # ── API: stats globales (rapide) ─────────────────────────
        if path == '/api/stats':
            stats = {}
            for s in SOURCES:
                fpath = os.path.join(OUTPUT_DIR, f'{s}_extracted.json')
                tpath = os.path.join(TRACKING_DIR, f'{s}_tracking.json')
                if not os.path.exists(fpath):
                    stats[s] = {'count': 0, 'iocs': 0, 'cves': 0, 'tracking': {}}
                    continue
                tracking = {}
                if os.path.exists(tpath):
                    try: tracking = json.load(open(tpath, encoding='utf-8'))
                    except: pass
                try:
                    data = json.load(open(fpath, encoding='utf-8'))
                    ioc_count = sum(len(e.get('iocs', [])) for e in data)
                    cve_count = sum(len(e.get('cves', [])) for e in data)
                    stats[s] = {'count': len(data), 'iocs': ioc_count, 'cves': cve_count, 'tracking': tracking}
                except Exception as e:
                    stats[s] = {'count': 0, 'iocs': 0, 'cves': 0, 'error': str(e), 'tracking': tracking}
            self._json(stats)
            return

        # ── Fichiers statiques ───────────────────────────────────
        super().do_GET()

    def _json(self, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[REQ] {args[0]} {args[1]}")

def start_server():
    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("", PORT), CTIHandler) as httpd:
            print("=" * 50)
            print("   CTI SHIELD – DASHBOARD SERVER")
            print("=" * 50)
            print(f"  URL     : http://localhost:{PORT}/dashboard/")
            print(f"  Data    : {OUTPUT_DIR}")
            print(f"  Max/src : {MAX_RECORDS} enregistrements")
            print(f"  CTRL+C  : Arrêter le serveur")
            print("=" * 50)
            webbrowser.open(f"http://localhost:{PORT}/dashboard/")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServeur arrêté.")
        sys.exit(0)
    except Exception as e:
        print(f"Erreur: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_server()
