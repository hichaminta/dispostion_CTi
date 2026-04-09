import json
import os
from datetime import datetime
from typing import List, Dict, Optional

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "runs.json")

class JSONDB:
    def __init__(self, filename=DATA_FILE):
        self.filename = filename
        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as f:
                json.dump([], f)

    def _read(self) -> List[Dict]:
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write(self, data: List[Dict]):
        with open(self.filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def get_runs(self) -> List[Dict]:
        return self._read()

    def get_run(self, id: int) -> Optional[Dict]:
        runs = self._read()
        for run in runs:
            if run.get('id') == id:
                return run
        return None

    def get_run_by_external_id(self, run_id: str) -> Optional[Dict]:
        runs = self._read()
        for run in runs:
            if run.get('run_id') == run_id:
                return run
        return None

    def create_run(self, run_data: Dict) -> Dict:
        runs = self._read()
        new_id = len(runs) + 1
        run_data['id'] = new_id
        run_data['created_at'] = datetime.utcnow().isoformat()
        run_data['updated_at'] = run_data['created_at']
        run_data['steps'] = []
        runs.append(run_data)
        self._write(runs)
        return run_data

    def update_run(self, run_id: str, run_data: Dict):
        runs = self._read()
        for i, run in enumerate(runs):
            if run.get('run_id') == run_id:
                runs[i].update(run_data)
                runs[i]['updated_at'] = datetime.utcnow().isoformat()
                self._write(runs)
                return runs[i]
        return None

    def update_step(self, run_id: str, step_data: Dict):
        runs = self._read()
        for i, run in enumerate(runs):
            if run.get('run_id') == run_id:
                if 'steps' not in runs[i]:
                    runs[i]['steps'] = []

                found = False
                for j, step in enumerate(runs[i]['steps']):
                    if step['step_name'] == step_data['step_name']:
                        # Preserve existing logs when updating step
                        existing_logs = runs[i]['steps'][j].get('logs', [])
                        runs[i]['steps'][j].update(step_data)
                        if 'logs' not in step_data:
                            runs[i]['steps'][j]['logs'] = existing_logs
                        found = True
                        break

                if not found:
                    if 'logs' not in step_data:
                        step_data['logs'] = []
                    runs[i]['steps'].append(step_data)

                runs[i]['updated_at'] = datetime.utcnow().isoformat()
                self._write(runs)
                return runs[i]
        return None

    def append_log(self, run_id: str, step_name: str, line: str):
        """Append a single log line to the specified step's logs list."""
        runs = self._read()
        for i, run in enumerate(runs):
            if run.get('run_id') == run_id:
                if 'steps' not in runs[i]:
                    runs[i]['steps'] = []

                # Find or create the step
                found = False
                for j, step in enumerate(runs[i]['steps']):
                    if step['step_name'] == step_name:
                        if not isinstance(runs[i]['steps'][j].get('logs'), list):
                            runs[i]['steps'][j]['logs'] = []
                        runs[i]['steps'][j]['logs'].append(line)
                        found = True
                        break

                if not found:
                    runs[i]['steps'].append({
                        'step_name': step_name,
                        'status': 'running',
                        'logs': [line],
                        'ioc_count': 0,
                        'cve_count': 0,
                    })

                runs[i]['updated_at'] = datetime.utcnow().isoformat()
                self._write(runs)
                return
        return None

    def get_logs(self, run_id: str, step_name: Optional[str] = None) -> List[str]:
        """Get all logs for a run, optionally filtered by step name."""
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

    def clear_runs(self):
        """Delete all runs and reset the file."""
        self._write([])

db = JSONDB()
