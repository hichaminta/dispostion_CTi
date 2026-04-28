import os
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MergeEnrichment")

BASE_DIR = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi"
SRC_DIR = os.path.join(BASE_DIR, "output_enrichment copy")
DST_DIR = os.path.join(BASE_DIR, "output_enrichment")

def merge_files():
    if not os.path.exists(SRC_DIR):
        logger.error(f"Source dir not found: {SRC_DIR}")
        return

    if not os.path.exists(DST_DIR):
        os.makedirs(DST_DIR)

    for filename in os.listdir(SRC_DIR):
        if not filename.endswith(".json"):
            continue
        
        src_path = os.path.join(SRC_DIR, filename)
        dst_path = os.path.join(DST_DIR, filename)
        
        try:
            with open(src_path, "r", encoding="utf-8") as f:
                src_data = json.load(f)
            
            if os.path.exists(dst_path):
                with open(dst_path, "r", encoding="utf-8") as f:
                    dst_data = json.load(f)
                
                if isinstance(src_data, list) and isinstance(dst_data, list):
                    # Merge and deduplicate by 'id' or 'value'
                    existing_ids = {item.get('id') or item.get('value') for item in dst_data}
                    new_items = [item for item in src_data if (item.get('id') or item.get('value')) not in existing_ids]
                    
                    merged_data = dst_data + new_items
                    logger.info(f"Merged {len(new_items)} new items into {filename}")
                else:
                    merged_data = src_data
                    logger.info(f"Overwriting {filename} (not a list)")
            else:
                merged_data = src_data
                logger.info(f"Copied {filename}")

            with open(dst_path, "w", encoding="utf-8") as f:
                json.dump(merged_data, f, indent=4)
                
        except Exception as e:
            logger.error(f"Error merging {filename}: {e}")

if __name__ == "__main__":
    merge_files()
