import asyncio
import os
import sys

# Configuration des chemins d'accès
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dotenv import load_dotenv
env_path = os.path.abspath(os.path.join(BASE_DIR, '..', '.env'))
load_dotenv(env_path, override=True)

# Import des classes core
from core.analyzer import LeakAnalyzer
from core.intelligence import IntelligenceAgent

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Runner pour le Corrélateur Quotidien (Daily Correlator) de l'IntelligenceAgent")
    parser.add_argument("--data-dir", type=str, default="../data/leaks", help="Chemin vers le dossier contenant les données (défaut: ../data/leaks)")
    parser.add_argument("--channel", type=str, help="Canal spécifique à traiter (ex: Jabaroot)")
    parser.add_argument("--date", type=str, help="Date spécifique à traiter (ex: 2026-04-08)")
    args = parser.parse_args()

    # Déterminer le chemin absolu pour data_dir
    if not os.path.isabs(args.data_dir):
        data_dir = os.path.abspath(os.path.join(BASE_DIR, args.data_dir))
    else:
        data_dir = args.data_dir

    if not os.path.exists(data_dir):
        print(f"[ERROR] Le dossier data n'existe pas : {data_dir}")
        return

    print("====================================================")
    print("   DAILY CORRELATOR RUNNER (Intelligence Agent)     ")
    print("====================================================")
    
    print("[*] Initialisation de LeakAnalyzer et IntelligenceAgent...")
    analyzer = LeakAnalyzer()
    intel_agent = IntelligenceAgent(BASE_DIR)

    channels_to_process = [args.channel] if args.channel else os.listdir(data_dir)

    for channel in channels_to_process:
        channel_path = os.path.join(data_dir, channel)
        if not os.path.isdir(channel_path):
            continue

        dates_to_process = [args.date] if args.date else os.listdir(channel_path)
        for date_str in dates_to_process:
            date_path = os.path.join(channel_path, date_str)
            if not os.path.isdir(date_path):
                continue
            
            leaks_file = os.path.join(date_path, "leaks.json")
            if os.path.exists(leaks_file):
                print(f"\n[+] Traitement de {leaks_file} pour le canal {channel}...")
                try:
                    await intel_agent.process_daily_leaks(leaks_file, analyzer, channel)
                except Exception as e:
                    print(f"[ERROR] Échec lors du traitement de {leaks_file}: {e}")
            else:
                if args.date:
                    print(f"[-] Aucun fichier leaks.json trouvé dans {date_path}")

    print("\n[+] Fin de l'exécution du Corrélateur Quotidien.")

if __name__ == "__main__":
    asyncio.run(main())
