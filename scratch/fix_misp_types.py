import os
import json

misp_run_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_misp\run_20260423_125208"

def get_misp_type(internal_type, value):
    mapping = {
        "ip": "ip-dst",
        "domain": "domain",
        "url": "url",
        "sha256": "sha256",
        "md5": "md5",
        "sha1": "sha1",
        "email": "email-src"
    }
    if internal_type == "hashe":
        vlen = len(value)
        if vlen == 32: return "md5"
        if vlen == 40: return "sha1"
        if vlen == 64: return "sha256"
        return "hash"
    return mapping.get(internal_type, internal_type)

if os.path.exists(misp_run_path):
    for root, dirs, files in os.walk(misp_run_path):
        for file in files:
            if not file.endswith(".json") or file == "manifest_tracking.json":
                continue
            
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                changed = False
                if isinstance(data, list):
                    for item in data:
                        event = item.get("Event", {})
                        attrs = event.get("Attribute", [])
                        for attr in attrs:
                            old_type = attr.get("type")
                            new_type = get_misp_type(old_type, attr.get("value", ""))
                            if old_type != new_type:
                                attr["type"] = new_type
                                changed = True
                
                if changed:
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2)
                    print(f"Fixed types in {path}")
            except Exception as e:
                print(f"Error fixing {path}: {e}")
