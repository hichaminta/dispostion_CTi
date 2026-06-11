import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from pymongo import MongoClient

DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "runs.json")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cti_db")

class MongoDB:
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_URI)
            self.db = self.client[MONGO_DB_NAME]
            self.collection = self.db["runs"]
            self.intel_collection = self.db["leaks_intel"]
            self._migrate_if_needed()
            self._migrate_intel_if_needed()
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")

    def _migrate_if_needed(self):
        # Migrate runs.json if MongoDB runs collection is empty but runs.json exists and has data
        if self.collection.count_documents({}) == 0:
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, 'r', encoding="utf-8") as f:
                        data = json.load(f)
                        if data and isinstance(data, list):
                            # Insert all runs into MongoDB
                            for run in data:
                                # Ensure we don't have _id conflicts if it was somehow in json
                                if "_id" in run:
                                    del run["_id"]
                            self.collection.insert_many(data)
                            print(f"Migrated {len(data)} runs from {DATA_FILE} to MongoDB.")
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    print(f"Error during migration: {e}")

    def _migrate_intel_if_needed(self):
        INTEL_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "leak_data_integration", "results", "leaks_intel.json"))
        if self.intel_collection.count_documents({}) == 0:
            if os.path.exists(INTEL_FILE):
                try:
                    with open(INTEL_FILE, 'r', encoding="utf-8") as f:
                        data = json.load(f)
                        if data and isinstance(data, list):
                            for record in data:
                                if "_id" in record:
                                    del record["_id"]
                            self.intel_collection.insert_many(data)
                            print(f"Migrated {len(data)} intelligence records from {INTEL_FILE} to MongoDB.")
                except Exception as e:
                    print(f"Error during intelligence migration: {e}")

    def get_runs(self) -> List[Dict]:
        runs = list(self.collection.find({}))
        for run in runs:
            if '_id' in run:
                run['_id'] = str(run['_id'])  # Convert ObjectId to string for JSON serialization
        return runs

    def get_run(self, id: int) -> Optional[Dict]:
        run = self.collection.find_one({"id": id})
        if run and '_id' in run:
            run['_id'] = str(run['_id'])
        return run

    def get_run_by_external_id(self, run_id: str) -> Optional[Dict]:
        run = self.collection.find_one({"run_id": run_id})
        if run and '_id' in run:
            run['_id'] = str(run['_id'])
        return run

    def create_run(self, run_data: Dict) -> Dict:
        # Auto-increment logic for 'id'
        max_run = self.collection.find_one({}, sort=[("id", -1)])
        new_id = 1
        if max_run and "id" in max_run:
            new_id = max_run["id"] + 1
            
        run_data['id'] = new_id
        run_data['created_at'] = datetime.utcnow().isoformat()
        run_data['updated_at'] = run_data['created_at']
        run_data['steps'] = []
        
        result = self.collection.insert_one(run_data)
        run_data['_id'] = str(result.inserted_id)
        return run_data

    def update_run(self, run_id: str, run_data: Dict):
        # We need to filter out _id to avoid modification errors
        update_data = {k: v for k, v in run_data.items() if k != '_id'}
        update_data['updated_at'] = datetime.utcnow().isoformat()
        updated_run = self.collection.find_one_and_update(
            {"run_id": run_id},
            {"$set": update_data},
            return_document=True
        )
        if updated_run and '_id' in updated_run:
            updated_run['_id'] = str(updated_run['_id'])
        return updated_run

    def update_step(self, run_id: str, step_data: Dict):
        run = self.get_run_by_external_id(run_id)
        if not run:
            return None

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

        updated_run = self.collection.find_one_and_update(
            {"run_id": run_id},
            {"$set": {"steps": steps, "updated_at": datetime.utcnow().isoformat()}},
            return_document=True
        )
        if updated_run and '_id' in updated_run:
            updated_run['_id'] = str(updated_run['_id'])
        return updated_run

    def append_log(self, run_id: str, step_name: str, line: str):
        run = self.get_run_by_external_id(run_id)
        if not run:
            return None

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

        self.collection.update_one(
            {"run_id": run_id},
            {"$set": {"steps": steps, "updated_at": datetime.utcnow().isoformat()}}
        )

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
        result = self.collection.delete_one({"id": run_id})
        return result.deleted_count > 0

    def clear_runs(self):
        self.collection.delete_many({})

    def get_all_intel(self) -> List[Dict]:
        intel = list(self.intel_collection.find({}))
        for record in intel:
            if '_id' in record:
                record['_id'] = str(record['_id'])
        return intel

    def save_or_update_intel(self, intel_id: str, data: Dict):
        update_data = {k: v for k, v in data.items() if k != '_id'}
        self.intel_collection.update_one(
            {"intel_id": intel_id},
            {"$set": update_data},
            upsert=True
        )

    def delete_intel(self, intel_id: str) -> bool:
        result = self.intel_collection.delete_one({"intel_id": intel_id})
        return result.deleted_count > 0

db = MongoDB()
