import os
import json

LOCAL_TRACKING_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_tracking.json")

class BaseTracker:
    def __init__(self, source_name, tracking_type):
        self.source_name = source_name
        self.tracking_type = tracking_type

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
        data = self._load_local()
        key = f"{self.tracking_type}_{self.source_name}"
        return data.get(key, {})

    def save_tracking(self, tracking_data):
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

class EnrichmentTracker(BaseTracker):
    def __init__(self, source_name):
        super().__init__(source_name, "enrichment")
