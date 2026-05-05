import os
import json
import logging
from datetime import datetime
from .analyzer import LeakAnalyzer

logger = logging.getLogger("DailyCorrelator")

class DailyCorrelator:
    def __init__(self, base_dir):
        self.project_root = os.path.dirname(base_dir)
        self.analyzer = LeakAnalyzer()
        self.intel_file = os.path.join(base_dir, "results", "leaks_intel.json")

    async def correlate_day(self, target_date_str=None, force_all=False):
        """Performs correlation with two-pass logic: 1. Before earliest_modified, 2. After last_run."""
        tracking_list = self._load_tracking()
        if not isinstance(tracking_list, list):
            tracking_list = []
        
        # Load global boundaries from all channel tracks
        gap_start = None
        gap_end = None
        
        for entry in tracking_list:
            try:
                e_mod = entry.get("earliest_modified")
                l_run = entry.get("last_run")
                if e_mod and str(e_mod).strip():
                    dt = datetime.fromisoformat(str(e_mod).strip().replace("Z", "+00:00"))
                    if gap_start is None or dt < gap_start: gap_start = dt
                if l_run and str(l_run).strip():
                    dt = datetime.fromisoformat(str(l_run).strip().replace("Z", "+00:00"))
                    if gap_end is None or dt > gap_end: gap_end = dt
            except Exception as e:
                logger.warning(f"Error parsing tracking entry dates: {e}")

        intel_records = self._load_intel()
        
        # Identify records to process (Pass 1: Before Gap, Pass 2: After Gap)
        to_process = []
        for r in intel_records:
            try:
                rec_date = datetime.fromisoformat(r.get('leak_date').replace("Z", "+00:00"))
                # SKIP if inside the global gap, unless force_all is True
                if not force_all and gap_start and gap_end and gap_start <= rec_date <= gap_end:
                    continue
                to_process.append(r)
            except:
                to_process.append(r) # Process if date format is unknown

        if not to_process and not force_all:
            logger.info("No records outside of tracking interval to correlate.")
            # Still perform global correlation on existing records just in case
            await self._perform_global_correlation(intel_records)
            self._write_intel(intel_records)
            return

        print(f"\n[Correlator] Analyzing {len(to_process)} records...")
        
        # 1. Deep File Correlation
        for record in to_process:
            if not record.get("deep_correlation"):
                if record.get("extracted_files") or record.get("file_references"):
                    await self._perform_deep_file_correlation(record)

        # 2. Noise Cleanup
        await self._cleanup_noise(to_process, intel_records)
        
        # 3. Consolidation (Only for processed records)
        if len(to_process) > 1:
            await self._consolidate_campaigns_list(to_process, intel_records)
            
        # 4. Global Correlation (Across all records)
        await self._perform_global_correlation(intel_records)
        
        # Save updated records
        self._write_intel(intel_records)
        logger.info("Deep correlation and global LLM consolidation complete.")
        
        # Note: Correlation metadata is not saved to tracking.json to respect user format

        print("\n[+] Generating final intelligence reports...")
        try:
            from .reporter import LeakReporter
            reporter = LeakReporter(self.intel_file)
            reports_dir = os.path.join(os.path.dirname(self.intel_file), "..", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            for r in intel_records:
                intel_id = r["intel_id"]
                pdf_path = os.path.join(reports_dir, f"bulletin_{intel_id}.pdf")
                if reporter.generate_pdf_bulletin(intel_id, pdf_path):
                    print(f"  [REPORT] Generated PDF bulletin for {intel_id}")
            print("[+] Report generation completed.")
        except Exception as e:
            logger.error(f"Failed to generate reports after correlation: {e}")

    def _load_tracking(self):
        """Helper to load tracking for correlation logic."""
        path = os.path.join(os.path.dirname(self.intel_file), "..", "tracking.json")
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except Exception as e:
                logger.warning(f"Failed to load tracking data: {e}")
                return []
        return []

    def _save_tracking(self, tracking_list):
        """Helper to save tracking data after completing stages."""
        path = os.path.join(os.path.dirname(self.intel_file), "..", "tracking.json")
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(tracking_list, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save tracking data: {e}")

    async def _cleanup_noise(self, day_records, all_records):
        """Final strict LLM pass to remove any noise that survived previous filters."""
        to_remove = []
        for record in day_records:
            # Skip if already verified or consolidated
            if record.get("deep_correlation") or record.get("is_consolidated"):
                continue
                
            prompt = f"Strictly decide if this is a CORPORATE/GOVERNMENT data leak: '{record.get('summary_fr')}'. Respond with 'LEAK' or 'NOISE'."
            res = await self.analyzer._query_ai(prompt)
            if res and "NOISE" in res.upper():
                print(f"  [CLEANUP] Removing noise record: {record['intel_id']}")
                to_remove.append(record)
        
        for r in to_remove:
            if r in all_records:
                all_records.remove(r)

    async def _consolidate_campaigns_list(self, records_list, all_records):
        """Pass 1: Consolidate records in the current batch."""
        await self._perform_global_correlation(all_records) # Delegate to the global pass for perfect minimization

    async def _perform_global_correlation(self, all_records):
        """Identifies related leaks and merges them deterministically to MINIMIZE the number of incidents."""
        if len(all_records) < 2: return
        
        print("[Correlator] Performing Global Deterministic Consolidation...")
        
        # 1. Deterministic grouping based on Target Name Aliases
        aliases = {
            "وزارة الداخلية": "Ministère de l'Intérieur",
            "ministere de l'interieur": "Ministère de l'Intérieur",
            "ministère de l'intérieur": "Ministère de l'Intérieur",
            "cnops": "CNOPS",
            "cndp": "CNDP",
            "watiqa": "WATIQA",
            "etat civil": "CNDP"
        }
        
        # Normalize targets in all records
        for r in all_records:
            normalized = []
            for t in r["leak_metadata"]["target_organization"]:
                norm_t = t
                for k, v in aliases.items():
                    if k.lower() in t.lower():
                        norm_t = v
                        break
                normalized.append(norm_t)
            r["leak_metadata"]["target_organization"] = list(set(normalized))
            
        # 2. Group by Target Organization
        groups = {}
        for r in all_records:
            targets = r["leak_metadata"]["target_organization"]
            if not targets or "Unknown" in targets:
                # Group Unknowns by the exact same leak date (YYYY-MM-DD)
                date_key = r.get("leak_date", "").split("T")[0]
                groups.setdefault(f"Unknown_{date_key}", []).append(r["intel_id"])
            else:
                # Group by the organization name
                for t in targets:
                    groups.setdefault(t, []).append(r["intel_id"])
                    
        # 3. Filter groups that have more than 1 record
        groups_to_merge = [ids for ids in groups.values() if len(set(ids)) > 1]
        
        # 4. Execute Merge
        if groups_to_merge:
            for group_ids in groups_to_merge:
                unique_ids = list(set(group_ids))
                if len(unique_ids) > 1:
                    await self._merge_records(unique_ids, all_records)

    async def _merge_records(self, ids, all_records):
        """Merges a list of record IDs into a single master record with synthesized intelligence."""
        to_merge = [r for r in all_records if r['intel_id'] in ids]
        if len(to_merge) < 2: return

        master = to_merge[0]
        other_summaries = []
        for other in to_merge[1:]:
            # Combine files safely
            for f in other.get("file_references", []):
                if f not in master.setdefault("file_references", []):
                    master["file_references"].append(f)
            for f in other.get("extracted_files", []):
                if f not in master.setdefault("extracted_files", []):
                    master["extracted_files"].append(f)
            # Combine targets safely
            for t in other.get("leak_metadata", {}).get("target_organization", []):
                if t not in master["leak_metadata"]["target_organization"]:
                    master["leak_metadata"]["target_organization"].append(t)
            # Combine dates safely
            if "detected_dates" not in master: 
                master["detected_dates"] = [master.get("leak_date")]
            for d in other.get("detected_dates", [other.get("leak_date")]):
                if d not in master["detected_dates"]:
                    master["detected_dates"].append(d)
                    
            # Combine summaries for synthesis
            other_summaries.append(other.get("summary_fr", ""))
            # Mark as consolidated
            master["is_consolidated"] = True
            if other in all_records:
                all_records.remove(other)
        
        # Synthesize a unified summary
        prompt = f"Synthesize a single, professional French intelligence summary from these two reports:\n1. {master['summary_fr']}\n2. {' '.join(other_summaries)}\n\nOutput ONLY the synthesized summary text."
        new_summary = await self.analyzer._query_ai(prompt)
        if new_summary:
            master["summary_fr"] = new_summary.strip()
            
        print(f"  [CONSOLIDATION] Merged {len(ids)} records into {str(master['intel_id']).encode('ascii', 'replace').decode('ascii')} (Synthesized summary created)")

    async def _perform_deep_file_correlation(self, record):
        """Uses LLM to deeply correlate the leak summary with actual file artifacts."""
        file_paths = record.get("extracted_files", []) + record.get("file_references", [])
        if not file_paths:
            return

        # Gather samples from the files
        samples = []
        # Project root is two levels up from results folder
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(self.intel_file)))
        
        for rel_path in file_paths[:5]: # Max 5 files for context
            abs_path = os.path.join(project_root, "data", "leaks", rel_path)
            if os.path.exists(abs_path) and os.path.isfile(abs_path):
                print(f"    - Found file for sample: {abs_path}")
                # Try to read sample
                if abs_path.lower().endswith(('.csv', '.sql', '.json', '.txt', '.dbf')):
                    try:
                        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                            sample_text = f.read(1500)
                            samples.append(f"--- File: {os.path.basename(abs_path)} ---\n{sample_text}")
                            print(f"    - Sample extracted ({len(sample_text)} chars)")
                    except Exception as e: 
                        print(f"    - Failed to read sample: {e}")
        
        if not samples:
            print(f"    - No text samples could be extracted for {record['intel_id']}")
            return

        prompt = f"""
        DEEP CORRELATION TASK:
        Analyze the relationship between this leak report and the actual data files found.
        
        LEAK SUMMARY: {record.get('summary_fr')}
        TARGETS: {record.get('leak_metadata', {}).get('target_organization')}
        
        FILE SAMPLES:
        {" ".join(samples)}
        
        TASK:
        1. Does the file content PROVE the leak summary?
        2. Identify the exact data types found (e.g., CIN numbers, Emails, Passwords, Salary info).
        3. Determine if there is a 'Master File' or a critical database among them.
        4. Provide a technical 'Deep Correlation' summary in French (max 3 sentences).
        
        OUTPUT (Strict JSON):
        {{
            "is_proven": boolean,
            "data_types_confirmed": ["type1", "type2"],
            "master_file_found": "filename or null",
            "correlation_summary": "Summary in French"
        }}
        """
        
        try:
            ai_text = await self.analyzer._query_ai(prompt)
            if ai_text:
                cor_data = self.analyzer._parse_ai_json(ai_text)
                if cor_data:
                    # Update record with correlation data
                    record["deep_correlation"] = cor_data
                    # Enhance severity if proven critical
                    if cor_data.get("is_proven") and "password" in str(cor_data).lower():
                        record["leak_metadata"]["severity"] = "critical"
                    logger.info(f"Deep correlation updated for {record['intel_id']}")
        except Exception as e:
            logger.error(f"Deep correlation failed for {record['intel_id']}: {e}")

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
