import os
import json
import sys
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv

def migrate():
    load_dotenv(find_dotenv(), override=False)
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cti_db")

    client = MongoClient(MONGO_URI)
    db = client[MONGO_DB_NAME]
    collection = db["tracking"]

    try:
        with open("utils/local_tracking.json", "r") as f:
            local_data = json.load(f)
    except Exception as e:
        print(f"Error loading local_tracking.json: {e}")
        return

    count = 0
    for key, val in local_data.items():
        if "_" in key:
            track_type, source_name = key.split("_", 1)
            
            # update mongo
            collection.update_one(
                {"source_name": source_name, "type": track_type},
                {"$set": {"tracking_data": val}},
                upsert=True
            )
            count += 1

    print(f"Migration complete! {count} records migrated.")

if __name__ == "__main__":
    migrate()
