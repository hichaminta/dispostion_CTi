import os
import json
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv, find_dotenv

# Try to connect to MongoDB, fallback to local JSON
try:
    load_dotenv(find_dotenv(), override=False)
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cti_db")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    db = client[MONGO_DB_NAME]
    collection = db["tracking"]
    # Check connection
    client.admin.command('ping')
    USE_MONGO = True
except Exception:
    USE_MONGO = False

LOCAL_TRACKING_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_tracking.json")

class BaseTracker:
    def __init__(self, source_name, tracking_type):
        self.source_name = source_name
        self.tracking_type = tracking_type
        self._local_data = {}

    def _load_local(self):
        if os.path.exists(LOCAL_TRACKING_FILE):
            try:
                with open(LOCAL_TRACKING_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_local(self, data):
        try:
            with open(LOCAL_TRACKING_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def get_tracking(self):
        if USE_MONGO:
            try:
                doc = collection.find_one({"source_name": self.source_name, "type": self.tracking_type})
                if doc and "tracking_data" in doc:
                    return doc["tracking_data"]
            except Exception:
                pass
        
        # Fallback to local
        data = self._load_local()
        key = f"{self.tracking_type}_{self.source_name}"
        return data.get(key, {})

    def save_tracking(self, tracking_data):
        if USE_MONGO:
            try:
                collection.update_one(
                    {"source_name": self.source_name, "type": self.tracking_type},
                    {"$set": {"tracking_data": tracking_data}},
                    upsert=True
                )
                return
            except Exception:
                pass

        # Fallback to local
        data = self._load_local()
        key = f"{self.tracking_type}_{self.source_name}"
        data[key] = tracking_data
        self._save_local(data)

class ExtractionTracker(BaseTracker):
    def __init__(self, source_name):
        super().__init__(source_name, "extraction")

class SourceTracker(BaseTracker):
    def __init__(self, source_name):
        super().__init__(source_name, "collection")
