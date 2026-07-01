import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("IntelligenceAgent")

class IntelligenceAgent:
    def __init__(self, base_dir):
        self.results_dir = os.path.join(base_dir, "output", "results")
        os.makedirs(self.results_dir, exist_ok=True)
        self.intel_file = os.path.join(self.results_dir, "leaks_intel.json")

    def save_intel(self, analysis_data, metadata, channel_name, leak_date=None):
        """Saves a purified leak record without the raw chat message."""
        
        # Default to current date if not provided
        if not leak_date:
            leak_date = datetime.now().strftime('%Y-%m-%d')
        
        # 1. Filter out politics or noise (Extra safety)
        if not analysis_data.get("is_leak"):
            return None

        # 2. Map the structured data
        extracted_files = metadata.get("extracted_files", [])
        main_file = metadata.get("file_path")
        if main_file and main_file not in extracted_files:
            extracted_files.append(main_file)

        if not extracted_files:
            logger.info(f"Skipping saving leak {metadata.get('id')} because it has no extracted file (user requirement).")
            return None

        targets = analysis_data.get('targets') or ['Unknown']
        target_prefix = targets[0][:3].upper() if targets and targets[0] else 'UNK'
        purified_record = {
            "intel_id": f"INTEL-{datetime.now().strftime('%Y%m%d')}-{target_prefix}-{metadata.get('id')}",
            "timestamp": datetime.now().isoformat(),
            "leak_date": leak_date,
            "detected_dates": [leak_date],
            "source_channel": channel_name,
            "leak_metadata": {
                "target_organization": analysis_data.get("targets", ["Unknown"]),
                "leak_type": analysis_data.get("leak_type", "Unknown"),
                "severity": analysis_data.get("severity", "low"),
                "confidence_score": analysis_data.get("confidence", 0)
            },
            "extracted_data": analysis_data.get("entities", {}),
            "file_references": [],
            "extracted_files": extracted_files,
            "summary_fr": analysis_data.get("summary", "Aucun résumé")
        }

        # 3. Save to intelligence database (Correlation will be done by DailyCorrelator via LLM)
        intel_list = self._load_intel()
        
        # Ensure file_references is a list
        purified_record["file_references"] = [purified_record.pop("file_reference")] if purified_record.get("file_reference") else []
        
        # Avoid exact duplicates by checking intel_id
        existing_idx = next((i for i, r in enumerate(intel_list) if r.get("intel_id") == purified_record["intel_id"]), None)
        
        if existing_idx is not None:
            # Update existing record
            existing = intel_list[existing_idx]
            
            # Merge file references
            for f in purified_record.get("file_references", []):
                if f not in existing.get("file_references", []):
                    existing.setdefault("file_references", []).append(f)
                    
            # Merge extracted files
            for f in purified_record.get("extracted_files", []):
                if f not in existing.get("extracted_files", []):
                    existing.setdefault("extracted_files", []).append(f)
                    
            intel_list[existing_idx] = existing
            logger.info(f"Updated existing intel record: {purified_record['intel_id']}")
        else:
            # Append new record
            intel_list.append(purified_record)
            logger.info(f"!!! INTEL GENERATED !!! Saved to {self.intel_file}")
            
        self._write_intel(intel_list)
        return purified_record

    def _load_intel(self):
        if os.path.exists(self.intel_file):
            try:
                with open(self.intel_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _write_intel(self, data):
        with open(self.intel_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    async def process_daily_leaks(self, leaks_file_path, analyzer, channel_name="Jabaroot"):
        """Reads a day's leaks.json, sends the full list to LLM for perfect correlation, and saves the final incidents."""
        if not os.path.exists(leaks_file_path):
            return

        with open(leaks_file_path, 'r', encoding='utf-8') as f:
            leaks = json.load(f)
            
        if not leaks:
            return

        # Extract the date from the folder name
        date_str = os.path.basename(os.path.dirname(leaks_file_path))
        
        # Prepare data for LLM (only sending necessary parts to save tokens)
        prompt_data = []
        for l in leaks:
            if l.get("analysis", {}).get("is_leak"):
                prompt_data.append({
                    "id": l.get("id"),
                    "date": l.get("date"),
                    "summary": l.get("analysis", {}).get("summary"),
                    "targets": l.get("analysis", {}).get("targets", []),
                    "severity": l.get("analysis", {}).get("severity"),
                    "files": l.get("metadata", {}).get("extracted_files", []) + ([l.get("metadata", {}).get("file_path")] if l.get("metadata", {}).get("file_path") else []),
                    "is_threat_only": not l.get("metadata", {}).get("has_media")
                })

        if not prompt_data:
            return

        prompt = f"""
        CORRELATION AND MAPPING TASK:
        Here are the Telegram leaks detected on {date_str} for channel {channel_name}.
        Your task is to correlate and map these messages into FINAL Intelligence Incidents.
        
        RULES:
        1. If a message is a threat (تهديد) and another message contains the actual file/archive for the SAME target organization, you MUST MERGE them into ONE single incident.
        2. A final incident should ideally have an extracted file.
        3. The ONLY case where an incident has no file is if it is a pure threat and NO file was detected that day for that target.
        4. Normalize the target names (e.g., 'CNOPS' and 'CNOPS', 'Ministère de l'Intérieur' and 'وزارة الداخلية' are the same).
        5. Provide a unified summary for merged incidents in French.
        
        DATA:
        {json.dumps(prompt_data, ensure_ascii=False)}
        
        OUTPUT FORMAT (Strict JSON ONLY):
        {{
            "incidents": [
                {{
                    "target_organization": ["Target Name"],
                    "leak_type": "PII/Database/Credentials/Other",
                    "severity": "high",
                    "summary_fr": "Unified summary of the incident...",
                    "extracted_files": ["path1", "path2"],
                    "original_ids": [51, 53]
                }}
            ]
        }}
        """
        
        print(f"[IntelligenceAgent] Sending {len(prompt_data)} records from {date_str} to LLM for mapping...")
        try:
            ai_text = await analyzer._query_ai(prompt)
            if not ai_text:
                logger.error("LLM returned empty response for daily mapping.")
                return

            mapped_data = analyzer._parse_ai_json(ai_text)
            if not mapped_data or "incidents" not in mapped_data:
                logger.error("Failed to parse LLM mapping response.")
                return

            intel_list = self._load_intel()
            
            for inc in mapped_data["incidents"]:
                # Create a unique ID based on the first original ID robustly
                orig_ids = inc.get("original_ids", ["0"])
                base_id = orig_ids[0] if isinstance(orig_ids, list) and orig_ids else "0"
                
                targets = inc.get("target_organization", ["UNK"])
                target_name = targets[0] if isinstance(targets, list) and targets else "UNK"
                target_prefix = str(target_name)[:3].upper() if target_name else "UNK"
                
                intel_id = f"INTEL-{datetime.now().strftime('%Y%m%d')}-{target_prefix}-{base_id}"
                
                final_record = {
                    "intel_id": intel_id,
                    "timestamp": datetime.now().isoformat(),
                    "leak_date": date_str,
                    "detected_dates": [date_str],
                    "source_channel": channel_name,
                    "leak_metadata": {
                        "target_organization": inc.get("target_organization", ["Unknown"]),
                        "leak_type": inc.get("leak_type", "Unknown"),
                        "severity": inc.get("severity", "high"),
                        "confidence_score": 1.0
                    },
                    "extracted_data": {"emails": [], "ips": [], "urls": [], "credentials": []},
                    "file_references": [],
                    "extracted_files": inc.get("extracted_files", []),
                    "summary_fr": inc.get("summary_fr", "Aucun résumé")
                }
                
                # Check for duplicates
                existing_idx = next((i for i, r in enumerate(intel_list) if r.get("intel_id") == intel_id), None)
                if existing_idx is not None:
                    intel_list[existing_idx] = final_record
                else:
                    intel_list.append(final_record)
                    
            self._write_intel(intel_list)
            print(f"  -> Generated {len(mapped_data['incidents'])} consolidated incidents for {date_str}.")
            
        except Exception as e:
            logger.error(f"Error processing daily leaks for {date_str}: {e}")
