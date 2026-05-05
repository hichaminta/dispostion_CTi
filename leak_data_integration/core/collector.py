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
                                if file_size_mb > 10 and i >= 100:
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

    async def start(self):
        logger.info("Starting Telegram Collector...")

        ai_ready = await self.analyzer.test_connection()
        if not ai_ready:
            logger.warning("AI may be unavailable. Falling back to Regex only.")

        await self.client.start(phone=self.phone)
        logger.info("Connected to Telegram!")

        # === Determine scan boundaries ===
        env_start_date = self.tracking_data.get("start_date", "2026-04-08")
        try:
            since_date = datetime.strptime(env_start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except:
            since_date = datetime(2026, 4, 8, tzinfo=timezone.utc)

        # === Load skip interval from tracking.json ===
        gap_start = None
        gap_end = None

        earliest_str = self.tracking_data.get("earliest_modified")
        last_run_str = self.tracking_data.get("last_run")

        if earliest_str and last_run_str:
            try:
                gap_start = datetime.fromisoformat(earliest_str).astimezone(timezone.utc)
                gap_end = datetime.fromisoformat(last_run_str).astimezone(timezone.utc)
            except Exception as e:
                logger.warning(f"Could not parse tracking dates: {e}")

        # === Display strategy ===
        print("\n" + "="*50)
        print("   CTI PLATFORM - COLLECTION STRATEGY")
        print(f"   > Start Date : {since_date.date()}")
        if gap_start and gap_end:
            print(f"   > SKIP ZONE  : {gap_start.date()} -> {gap_end.date()}")
        else:
            print("   > SKIP ZONE  : None (Full scan)")
        print("="*50 + "\n")

        for channel_url in self.channels:
            try:
                entity = await self.client.get_entity(channel_url)
                channel_name = getattr(entity, 'title', channel_url)
                logger.info(f"Monitoring: {channel_name}")

                processed_count = 0
                skipped_count = 0

                # Process newest to oldest (default Telethon behavior) to avoid offset_date quirks
                async for message in self.client.iter_messages(entity):
                    m_date = message.date.astimezone(timezone.utc)

                    # Stop entirely if we go back further than the start date
                    if m_date < since_date:
                        break
                    
                    # === SKIP WALL: Ignore anything inside the tracking interval ===
                    if gap_start and gap_end and gap_start <= m_date <= gap_end:
                        skipped_count += 1
                        if skipped_count % 10 == 1:
                            print(f"   [SKIP] {m_date.date()} is inside tracking interval. Skipping...")
                        continue

                    # === PROCESS NEW/OLD MESSAGES OUTSIDE THE GAP ===
                    content = message.text or "[Media/File]"
                    logger.info(f"| PROCESSING | {m_date.strftime('%Y-%m-%d %H:%M')} - {content[:60].replace(chr(10), ' ')}...")

                    await self.process_message(message=message, channel_entity=entity)
                    processed_count += 1

                    # Update tracking boundaries
                    if not gap_start or m_date < gap_start:
                        self.tracking_data["earliest_modified"] = m_date.isoformat()
                        gap_start = m_date
                    if not gap_end or m_date > gap_end:
                        self.tracking_data["last_run"] = m_date.isoformat()
                        gap_end = m_date

                logger.info(f"Done. Processed: {processed_count}, Skipped: {skipped_count}")
                if processed_count > 0:
                    self._save_tracking()

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
                                    if file_size_mb > 10 and i >= 100:
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
            if leak_record["metadata"]["file_path"].lower().endswith(('.zip', '.ziip', '.rar', '.dbf', '.sql')):
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
