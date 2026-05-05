import os
import json
import sys

# Ensure UTF-8 for console output
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Add script directory to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from core.intelligence import IntelligenceAgent
from core.correlator import DailyCorrelator
from datetime import datetime
import asyncio

async def migrate_intel():
    print("====================================================")
    print("   INTELLIGENCE RE-PROCESSING & CORRELATION        ")
    print("====================================================")
    
    # Project root is one level up from this script
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    integration_dir = os.path.join(project_root, "leak_data_integration")
    intel_agent = IntelligenceAgent(integration_dir)
    correlator = DailyCorrelator(integration_dir)
    
    leaks_base_path = os.path.join(project_root, "data", "leaks")
    if not os.path.exists(leaks_base_path):
        print(f"[!] Leaks directory not found: {leaks_base_path}")
        return

    processed_count = 0
    unique_dates = set()

    # 1. First Pass: Re-generate Intelligence from raw leaks
    for root, dirs, files in os.walk(leaks_base_path):
        if "leaks.json" in files:
            file_path = os.path.join(root, "leaks.json")
            date_dir = os.path.basename(root)
            unique_dates.add(date_dir)
            print(f"[*] Processing {file_path}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    leaks = json.load(f)
                    if not isinstance(leaks, list):
                        continue
                        
                for leak in leaks:
                    analysis = leak.get("analysis")
                    metadata = leak.get("metadata")
                    channel = leak.get("channel", "Unknown")
                    leak_date = leak.get("date", datetime.now().strftime('%Y-%m-%d'))
                    
                    if analysis and metadata:
                        print(f"  - Saving intelligence for leak {leak.get('id')} ({leak_date})...")
                        intel_agent.save_intel(analysis, metadata, channel, leak_date)
                        processed_count += 1
            except Exception as e:
                print(f"  [ERROR] Failed to process {file_path}: {e}")

    # 2. Second Pass: Deep Correlation (Daily Layer)
    print("\n[Layer 2] Starting Deep Correlation Layer...")
    for date_str in unique_dates:
        # Check if date format is YYYY-MM-DD
        if len(date_str) == 10 and date_str.count("-") == 2:
            print(f"[*] Correlating date: {date_str}...")
            await correlator.correlate_day(date_str)

    print("====================================================")
    print(f"   SUCCESS: Re-processed {processed_count} leaks.")
    print(f"   Daily Correlation applied to {len(unique_dates)} dates.")
    print(f"   Results saved to: {intel_agent.intel_file}")
    print("====================================================")

if __name__ == "__main__":
    asyncio.run(migrate_intel())
