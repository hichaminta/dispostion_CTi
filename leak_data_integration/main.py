import asyncio
import sys
import os

INTEL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(INTEL_DIR)

if INTEL_DIR not in sys.path:
    sys.path.insert(0, INTEL_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.collector import TelegramCollector
from core.correlator import DailyCorrelator

async def main():
    print("====================================================")
    print("   DATA LEAK DETECTION & TRACKING PLATFORM         ")
    print("====================================================")
    
    config_path = os.path.join(INTEL_DIR, "config", "settings.yaml")
    collector = TelegramCollector(config_path=config_path)
    try:
        await collector.start()
    except KeyboardInterrupt:
        print("\n[!] Stopping collector...")
    except Exception as e:
        import traceback
        print(f"\n[ERROR] {e}")
        traceback.print_exc()

    print("\n====================================================")
    print("   STARTING LLM CORRELATION AND INTELLIGENCE       ")
    print("====================================================")
    
    correlator = DailyCorrelator(INTEL_DIR)
    try:
        await correlator.correlate_day()
    except Exception as e:
        import traceback
        print(f"\n[ERROR] during correlation: {e}")
        traceback.print_exc()
        
    print("\n[+] Intelligence Pipeline Completed Successfully.")

if __name__ == "__main__":
    asyncio.run(main())
