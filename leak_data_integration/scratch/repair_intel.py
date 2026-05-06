import os
import json
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RepairScript")

PROJECT_ROOT = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\leak_data_integration"
DATA_ROOT = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\data\leaks"
INTEL_FILE = os.path.join(PROJECT_ROOT, "results", "leaks_intel.json")

def repair():
    if not os.path.exists(INTEL_FILE):
        logger.error(f"Intel file not found: {INTEL_FILE}")
        return

    with open(INTEL_FILE, 'r', encoding='utf-8') as f:
        intel_records = json.load(f)

    # Map to help find the original files
    # We will search in all channels/dates/leaks.json
    all_leaks_data = []
    for channel in os.listdir(DATA_ROOT):
        channel_dir = os.path.join(DATA_ROOT, channel)
        if not os.path.isdir(channel_dir): continue
        for date_f in os.listdir(channel_dir):
            date_dir = os.path.join(channel_dir, date_f)
            if not os.path.isdir(date_dir): continue
            leaks_json = os.path.join(date_dir, "leaks.json")
            if os.path.exists(leaks_json):
                with open(leaks_json, 'r', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_leaks_data.extend(data)
                    except:
                        pass

    # Index leaks by ID for quick lookup
    leaks_by_id = {str(l['id']): l for l in all_leaks_data}

    repaired_count = 0
    for record in intel_records:
        intel_id = record['intel_id']
        # The intel_id format is INTEL-YYYYMMDD-TGT-MSGID
        parts = intel_id.split('-')
        if len(parts) < 4: continue
        msg_id = parts[-1]
        
        if msg_id in leaks_by_id:
            leak_orig = leaks_by_id[msg_id]
            meta = leak_orig.get('metadata', {})
            
            # Re-link files
            extracted = meta.get('extracted_files', [])
            main_file = meta.get('file_path')
            
            current_files = record.setdefault('extracted_files', [])
            
            added = False
            for f in extracted:
                if f not in current_files:
                    current_files.append(f)
                    added = True
            if main_file and main_file not in current_files:
                current_files.append(main_file)
                added = True
            
            if added:
                repaired_count += 1
                logger.info(f"Repaired files for {intel_id}")

    if repaired_count > 0:
        with open(INTEL_FILE, 'w', encoding='utf-8') as f:
            json.dump(intel_records, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully repaired {repaired_count} records.")
    else:
        logger.info("No records needed repairing.")

if __name__ == "__main__":
    repair()
