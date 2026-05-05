import os
import json

base_path = r'c:\Users\Hicham\Desktop\PFE\dispostion_CTi\Sources_data'
target = {
    "earliest_modified": "2026-04-26T00:00:00+01:00",
    "last_run": "2026-05-04T12:18:52+01:00"
}

results = []

for root, dirs, files in os.walk(base_path):
    if 'tracking.json' in files:
        file_path = os.path.join(root, 'tracking.json')
        try:
            with open(file_path, 'r') as f:
                content = json.load(f)
                if content.get('earliest_modified') == target['earliest_modified'] or content.get('last_run') == target['last_run']:
                    results.append((file_path, content))
        except Exception as e:
            pass

print(json.dumps(results, indent=2))
