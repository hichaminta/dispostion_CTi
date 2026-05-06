import os
import json
import asyncio
import logging
from datetime import datetime, timezone
from telethon import TelegramClient
from dotenv import load_dotenv

load_dotenv()

from .analyzer import LeakAnalyzer
from .intelligence import IntelligenceAgent

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TelegramCollector")


class TelegramCollector:
    def __init__(self, config_path="config/settings.yaml"):
        import yaml
        self.api_id = os.getenv("TELEGRAM_API_ID")
        self.api_hash = os.getenv("TELEGRAM_API_HASH")
        self.phone = os.getenv("TELEGRAM_PHONE")

        if not self.api_id or not self.api_hash:
            raise ValueError("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env file")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = {}

        self.channels = self.config.get('telegram', {}).get('channels', [])

        session_path = os.path.join(os.getcwd(), "telegram_leak_session")
        self.client = TelegramClient(session_path, self.api_id, self.api_hash)

        self.analyzer = LeakAnalyzer()
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.intel_agent = IntelligenceAgent(base_dir)

        # Tracking file
        integration_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up one level from 'core' to 'leak_data_integration'
        integration_dir = os.path.dirname(integration_dir)
        self.tracking_file = os.path.join(integration_dir, "tracking.json")
        self.tracking_data = self._load_tracking()

    def _load_tracking(self):
        if os.path.exists(self.tracking_file):
            try:
                with open(self.tracking_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_tracking(self):
        try:
            with open(self.tracking_file, 'w') as f:
                json.dump(self.tracking_data, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save tracking: {e}")

    def _extract_and_get_context(self, archive_path, extract_to):
        import zipfile, shutil
        context_parts = []
        found_files_paths = []
        try:
            subfolder_name = os.path.basename(archive_path) + "_extracted"
            extract_path = os.path.join(extract_to, subfolder_name)
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
            os.makedirs(extract_path, exist_ok=True)

            if archive_path.lower().endswith(('.zip', '.ziip')):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            elif archive_path.lower().endswith('.rar'):
                try:
                    import patoolib
                    patoolib.extract_archive(archive_path, outdir=extract_path, verbosity=-1)
                except ImportError:
                    logger.warning("patoolib not installed. Skipping RAR.")
                    return None, []

            for root, _, files in os.walk(extract_path):
                for file in files:
                    full_p = os.path.join(root, file)
                    found_files_paths.append(full_p)

            found_files = [os.path.basename(p) for p in found_files_paths]
            if found_files:
                context_parts.append(f"Archive contains {len(found_files)} files: {', '.join(found_files[:20])}")

            for full_p in found_files_paths:
                file = os.path.basename(full_p)
                if file.lower().endswith(('.txt', '.sql', '.csv', '.json', '.log')):
                    try:
                        file_size_mb = os.path.getsize(full_p) / (1024 * 1024)
                        line_count = 0
                        sample_lines = []
                        with open(full_p, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f):
                                if file_size_mb > 500 and i >= 100:
                                    line_count = "100+ (Volumineux)"
                                    break
                                if isinstance(line_count, int):
                                    line_count += 1
                                if i < 100:
                                    sample_lines.append(line)
                        
                        context_parts.append(f"--- File: {file} (Size: {file_size_mb:.2f} MB, Total Lines: {line_count}) ---\n" + "".join(sample_lines))
                    except Exception as e:
                        logger.error(f"Error reading extracted file {file}: {e}")


            return "\n\n".join(context_parts)[:6000], found_files_paths
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return None, []

    async def start(self, start_date_override=None):
        logger.info("Starting Telegram Collector...")

        ai_ready = await self.analyzer.test_connection()
        if not ai_ready:
            logger.warning("AI may be unavailable. Falling back to Regex only.")

        await self.client.start(phone=self.phone)
        logger.info("Connected to Telegram!")

        print("\n" + "="*50)
        print("   CTI PLATFORM - COLLECTION STRATEGY")
        print("="*50 + "\n")

        tracking_list = self.tracking_data if isinstance(self.tracking_data, list) else []
        self.tracking_data = tracking_list # Ensure internal state is the list

        for channel_url in self.channels:
            try:
                entity = await self.client.get_entity(channel_url)
                channel_name = getattr(entity, 'title', channel_url)
                
                # Find specific tracking for this channel (Flexible matching)
                channel_track = next((t for t in tracking_list if 
                    (channel_name and channel_name.lower() in t.get("group_name", "").lower()) or 
                    (t.get("group_name") and t.get("group_name", "").lower() in channel_name.lower()) or
                    channel_url.split('/')[-1].lower() in t.get("group_name", "").lower()
                ), None)
                
                if not channel_track:
                    # Create default entry if not found
                    channel_track = {
                        "group_name": channel_name,
                        "start_date": "2026-05-05",
                        "earliest_modified": None,
                        "last_run": None
                    }
                    tracking_list.append(channel_track)

                # Use override if provided, otherwise use tracking data
                since_date_str = start_date_override or channel_track.get("start_date", "2026-05-05")
                since_date = None
                
                # Try parsing different formats
                for fmt in ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"]:
                    try:
                        since_date = datetime.strptime(since_date_str, fmt)
                        break
                    except:
                        continue
                
                if not since_date:
                    since_date = datetime(2026, 5, 5, tzinfo=timezone.utc)

                gap_start = None
                gap_end = None
                earliest_str = channel_track.get("earliest_modified")
                last_run_str = channel_track.get("last_run")

                if earliest_str and last_run_str:
                    try:
                        gap_start = datetime.fromisoformat(earliest_str).astimezone()
                        gap_end = datetime.fromisoformat(last_run_str).astimezone()
                    except:
                        pass

                # Store initial gap boundaries to avoid skipping messages processed in the SAME run
                initial_gap_start = gap_start
                initial_gap_end = gap_end

                print(f"   [*] Channel: {channel_name}")
                print(f"   > Start Date : {since_date.date()}")
                if initial_gap_start and initial_gap_end:
                    print(f"   > SKIP ZONE  : {initial_gap_start.strftime('%H:%M')} -> {initial_gap_end.strftime('%H:%M')}")
                else:
                    print("   > SKIP ZONE  : None (Full scan)")
                
                logger.info(f"Monitoring: {channel_name}")

                processed_count = 0
                skipped_count = 0

                # Process newest to oldest (default Telethon behavior) to avoid offset_date quirks
                async for message in self.client.iter_messages(entity):
                    m_date = message.date.astimezone()

                    # Stop entirely if we go back further than the start date
                    if m_date.replace(tzinfo=None) < since_date.replace(tzinfo=None):
                        break
                    
                    # === SKIP WALL: Ignore anything inside the INITIAL tracking interval ===
                    if initial_gap_start and initial_gap_end and initial_gap_start <= m_date <= initial_gap_end:
                        skipped_count += 1
                        if skipped_count % 10 == 1:
                            print(f"   [SKIP] {m_date.strftime('%H:%M')} is inside initial tracking interval. Skipping...")
                        continue

                    # === PROCESS NEW/OLD MESSAGES OUTSIDE THE GAP ===
                    content = message.text or "[Media/File]"
                    logger.info(f"| PROCESSING | {m_date.strftime('%Y-%m-%d %H:%M')} - {content[:60].replace(chr(10), ' ')}...")

                    await self.process_message(message=message, channel_entity=entity)
                    processed_count += 1

                    # Update tracking boundaries for this channel
                    if not gap_start or m_date < gap_start:
                        channel_track["earliest_modified"] = m_date.isoformat()
                        gap_start = m_date
                    if not gap_end or m_date > gap_end:
                        channel_track["last_run"] = m_date.isoformat()
                        gap_end = m_date

                # Finalize tracking for this channel run
                # On met à jour le curseur même si 0 messages ont été traités
                # cela évite de re-scanner les mêmes messages au prochain run.
                now_local = datetime.now()
                
                if gap_end:
                    # On utilise la date du message le plus récent trouvé
                    channel_track["last_run"] = gap_end.isoformat()
                    channel_track["start_date"] = gap_end.strftime("%Y-%m-%d")
                else:
                    # Si aucun message n'a été traité (tous sautés ou aucun nouveau),
                    # on avance quand même le last_run à "maintenant" pour marquer le succès du scan.
                    channel_track["last_run"] = now_local.isoformat()

                logger.info(f"Done. Processed: {processed_count}, Skipped: {skipped_count}")
                self._save_tracking() # Always save to update state

            except Exception as e:
                logger.error(f"Error for {channel_url}: {e}")
                import traceback
                traceback.print_exc()

        logger.info("Collection finished. Disconnecting...")
        await self.client.disconnect()

    async def process_message(self, message, channel_entity=None):
        if not message:
            return False

        channel = channel_entity or await message.get_chat()
        channel_title = getattr(channel, 'title', 'Unknown_Channel')
        folder_name = "".join([c if c.isalnum() else "_" for c in channel_title])
        date_str = message.date.strftime('%Y-%m-%d')

        base_storage_path = self.config.get('storage', {}).get('base_path', './data/leaks')
        target_dir = os.path.join(base_storage_path, folder_name, date_str)
        os.makedirs(target_dir, exist_ok=True)
        leaks_file = os.path.join(target_dir, "leaks.json")

        leak_record = {
            "id": message.id,
            "date": message.date.isoformat(),
            "channel": channel_title,
            "content": message.message or "[Media/File]",
            "metadata": {
                "has_media": message.media is not None,
                "file_path": None,
                "extracted_files": []
            },
            "analysis": None
        }

        file_sample = ""
        if message.media:
            try:
                download_dir = os.path.join(target_dir, "downloads")
                os.makedirs(download_dir, exist_ok=True)
                
                # Check file size before download
                file_size = message.file.size if message.file else 0
                max_size = 200 * 1024 * 1024 # 200 MB
                
                if file_size > max_size:
                    logger.warning(f"File too large ({file_size / (1024*1024):.1f} MB). Skipping download.")
                    print(f"    [!] Fichier trop volumineux ({file_size / (1024*1024):.1f} MB) > Limite 200 MB. Skip.")
                    leak_record["metadata"]["file_path"] = "SKIPPED_TOO_LARGE"
                else:
                    # Real-time progress display
                    async def download_progress(current, total):
                        if total > 0:
                            percent = current / total * 100
                            mb_current = current / (1024 * 1024)
                            mb_total = total / (1024 * 1024)
                            # \r overwrites the current line to create a live progress bar
                            print(f"\r    [+] Téléchargement : {mb_current:.1f} MB / {mb_total:.1f} MB ({percent:.1f}%)", end="", flush=True)

                    print(f"    [+] Début du téléchargement du fichier rattaché...")
                    file_path = await message.download_media(file=download_dir, progress_callback=download_progress)
                    print() # New line after the progress bar finishes
                    
                    if file_path:
                        leak_record["metadata"]["file_path"] = os.path.relpath(file_path, base_storage_path)
                        # ... extraction and sampling ...
                    if file_path.lower().endswith(('.zip', '.ziip', '.rar')):
                        extracted_context, extracted_paths = self._extract_and_get_context(file_path, download_dir)
                        if extracted_context:
                            file_sample = extracted_context
                            leak_record["metadata"]["extracted_files"] = [os.path.relpath(p, base_storage_path) for p in extracted_paths]
                    elif file_path.lower().endswith(('.txt', '.log', '.sql', '.json', '.csv')):
                        try:
                            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                            line_count = 0
                            sample_lines = []
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                for i, line in enumerate(f):
                                    if file_size_mb > 500 and i >= 100:
                                        line_count = "100+ (Volumineux)"
                                        break
                                    if isinstance(line_count, int):
                                        line_count += 1
                                    if i < 100:
                                        sample_lines.append(line)
                            
                            file_sample = f"[METADATA]\nFile Size: {file_size_mb:.2f} MB\nTotal Lines: {line_count}\n\n[SAMPLE (First 100 lines)]\n" + "".join(sample_lines)
                        except Exception as e:
                            logger.error(f"Error sampling direct file {file_path}: {e}")
            except Exception as e:
                logger.error(f"Failed to process media: {e}")

        analysis = await self.analyzer.analyze_leak(text=message.message or "", file_context=file_sample)

        # === HEURISTIC OVERRIDE: If it's an archive file in this channel, it's 100% a leak ===
        is_archive = False
        if leak_record["metadata"]["file_path"]:
            if leak_record["metadata"]["file_path"].lower().endswith(('.zip', '.ziip', '.rar', '.dbf', '.sql', '.xlsx', '.xls', '.xlsm', '.csv')):
                is_archive = True
        
        # If the LLM says it's not a leak, but we have a suspicious archive file, we KEEP it.
        if not analysis.get("is_leak", False) and not is_archive:
            logger.info(f"Skipping message {message.id} (Not a leak)")
            if leak_record["metadata"]["file_path"]:
                try:
                    full_path = os.path.join(base_storage_path, leak_record["metadata"]["file_path"])
                    if os.path.exists(full_path):
                        os.remove(full_path)
                        import shutil
                        extracted_dir = full_path + "_extracted"
                        if os.path.exists(extracted_dir):
                            shutil.rmtree(extracted_dir)
                except:
                    pass
            return False

        # Force analysis to say it's a leak if our heuristic caught it
        if is_archive and not analysis.get("is_leak", False):
            logger.info(f"Heuristic override: Message {message.id} has an archive file. Marking as LEAK.")
            analysis["is_leak"] = True
            if not analysis.get("title"):
                analysis["title"] = "Database Dump / Archive Leak"
            if not analysis.get("severity"):
                analysis["severity"] = "High"

        leak_record["analysis"] = analysis

        leaks_list = []
        if os.path.exists(leaks_file):
            try:
                with open(leaks_file, 'r', encoding='utf-8') as f:
                    leaks_list = json.load(f)
                    if not isinstance(leaks_list, list):
                        leaks_list = []
            except:
                leaks_list = []

        if any(l.get('id') == message.id for l in leaks_list):
            return True

        leaks_list.append(leak_record)
        with open(leaks_file, 'w', encoding='utf-8') as f:
            json.dump(leaks_list, f, indent=4, ensure_ascii=False)

        metadata_for_intel = leak_record["metadata"].copy()
        metadata_for_intel["id"] = leak_record["id"]
        self.intel_agent.save_intel(analysis, metadata_for_intel, channel_title, message.date.isoformat())
        logger.info(f"Saved leak {message.id} to {leaks_file}")
        return True
