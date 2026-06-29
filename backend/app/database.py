import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import uuid

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "store", "runs.json")
INTEL_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "leak_data_integration", "results", "leaks_intel.json"))

class LocalDB:
    def __init__(self):
        self._ensure_files()

    def _ensure_files(self):
        if not os.path.exists(DATA_FILE):
            try:
                os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
                with open(DATA_FILE, 'w', encoding="utf-8") as f:
                    json.dump([], f)
            except Exception:
                pass
        
        if not os.path.exists(INTEL_FILE):
            try:
                os.makedirs(os.path.dirname(INTEL_FILE), exist_ok=True)
                with open(INTEL_FILE, 'w', encoding="utf-8") as f:
                    json.dump([], f)
            except Exception:
                pass

    def _read_json(self, file_path) -> List[Dict]:
        try:
            with open(file_path, 'r', encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except Exception:
            return []

    def _write_json(self, file_path, data: List[Dict]):
        try:
            with open(file_path, 'w', encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"Error writing to {file_path}: {e}")

    # --- Runs Management ---
    
    def get_runs(self) -> List[Dict]:
        return self._read_json(DATA_FILE)

    def get_run(self, id: int) -> Optional[Dict]:
        runs = self.get_runs()
        for run in runs:
            if run.get("id") == id:
                return run
        return None

    def get_run_by_external_id(self, run_id: str) -> Optional[Dict]:
        runs = self.get_runs()
        for run in runs:
            if run.get("run_id") == run_id:
                return run
        return None

    def create_run(self, run_data: Dict) -> Dict:
        runs = self.get_runs()
        new_id = 1
        if runs and "id" in runs[-1]:
            new_id = runs[-1]["id"] + 1
            
        run_data['id'] = new_id
        if 'run_id' not in run_data:
            run_data['run_id'] = str(uuid.uuid4())
        run_data['created_at'] = datetime.utcnow().isoformat()
        run_data['updated_at'] = run_data['created_at']
        run_data['steps'] = []
        
        runs.append(run_data)
        self._write_json(DATA_FILE, runs)
        return run_data

    def update_run(self, run_id: str, run_data: Dict):
        runs = self.get_runs()
        updated_run = None
        for i, run in enumerate(runs):
            if run.get("run_id") == run_id:
                update_data = {k: v for k, v in run_data.items() if k != '_id'}
                update_data['updated_at'] = datetime.utcnow().isoformat()
                runs[i].update(update_data)
                updated_run = runs[i]
                break
        
        if updated_run:
            self._write_json(DATA_FILE, runs)
        return updated_run

    def update_step(self, run_id: str, step_data: Dict):
        runs = self.get_runs()
        updated_run = None
        for i, run in enumerate(runs):
            if run.get("run_id") == run_id:
                steps = run.get('steps', [])
                found = False
                for j, step in enumerate(steps):
                    if step['step_name'] == step_data['step_name']:
                        existing_logs = steps[j].get('logs', [])
                        steps[j].update(step_data)
                        if 'logs' not in step_data:
                            steps[j]['logs'] = existing_logs
                        found = True
                        break
                
                if not found:
                    if 'logs' not in step_data:
                        step_data['logs'] = []
                    steps.append(step_data)
                
                run['steps'] = steps
                run['updated_at'] = datetime.utcnow().isoformat()
                updated_run = run
                break

        if updated_run:
            self._write_json(DATA_FILE, runs)
        return updated_run

    def append_log(self, run_id: str, step_name: str, line: str):
        runs = self.get_runs()
        updated = False
        for i, run in enumerate(runs):
            if run.get("run_id") == run_id:
                steps = run.get('steps', [])
                found = False
                for j, step in enumerate(steps):
                    if step['step_name'] == step_name:
                        if not isinstance(steps[j].get('logs'), list):
                            steps[j]['logs'] = []
                        steps[j]['logs'].append(line)
                        found = True
                        break
                
                if not found:
                    steps.append({
                        'step_name': step_name,
                        'status': 'running',
                        'logs': [line],
                        'ioc_count': 0,
                        'cve_count': 0,
                    })
                
                run['steps'] = steps
                run['updated_at'] = datetime.utcnow().isoformat()
                updated = True
                break
        
        if updated:
            self._write_json(DATA_FILE, runs)

    def get_logs(self, run_id: str, step_name: Optional[str] = None) -> List[str]:
        run = self.get_run_by_external_id(run_id)
        if not run:
            return []
        all_logs = []
        for step in run.get('steps', []):
            if step_name is None or step['step_name'] == step_name:
                logs = step.get('logs', [])
                if isinstance(logs, list):
                    all_logs.extend([f"[{step['step_name']}] {l}" for l in logs])
                elif isinstance(logs, str) and logs:
                    all_logs.append(f"[{step['step_name']}] {logs}")
        return all_logs

    def delete_run(self, run_id: int) -> bool:
        runs = self.get_runs()
        initial_len = len(runs)
        runs = [r for r in runs if r.get("id") != run_id]
        if len(runs) < initial_len:
            self._write_json(DATA_FILE, runs)
            return True
        return False

    def clear_runs(self):
        self._write_json(DATA_FILE, [])

    # --- Intelligence Management ---
    
    def get_all_intel(self) -> List[Dict]:
        return self._read_json(INTEL_FILE)

    def save_or_update_intel(self, intel_id: str, data: Dict):
        intel_list = self.get_all_intel()
        updated = False
        update_data = {k: v for k, v in data.items() if k != '_id'}
        
        for i, record in enumerate(intel_list):
            if record.get("intel_id") == intel_id:
                intel_list[i].update(update_data)
                updated = True
                break
        
        if not updated:
            if "intel_id" not in update_data:
                update_data["intel_id"] = intel_id
            intel_list.append(update_data)
            
        self._write_json(INTEL_FILE, intel_list)

    def delete_intel(self, intel_id: str) -> bool:
        intel_list = self.get_all_intel()
        initial_len = len(intel_list)
        intel_list = [r for r in intel_list if r.get("intel_id") != intel_id]
        if len(intel_list) < initial_len:
            self._write_json(INTEL_FILE, intel_list)
            return True
        return False

db = LocalDB()
