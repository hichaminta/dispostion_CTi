import os
import json
import asyncio
import sys

# Ensure modules can be found
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from leak_data_integration.core.intelligence import IntelligenceAgent
from leak_data_integration.core.analyzer import LeakAnalyzer
from leak_data_integration.core.reporter import LeakReporter

INTEL_DIR = os.path.join(PROJECT_ROOT, "leak_data_integration")

async def run_pipeline():
    print("====================================================")
    print("   MIGRATION, MAPPING LLM & GÉNÉRATION RAPPORTS     ")
    print("====================================================")
    
    # 1. Reset and Repopulate via LLM Mapping
    intel_file = os.path.join(INTEL_DIR, "results", "leaks_intel.json")
    agent = IntelligenceAgent(INTEL_DIR)
    agent._write_intel([]) # Clear the old database
    
    analyzer = LeakAnalyzer()
    jabaroot_dir = os.path.join(PROJECT_ROOT, "data", "leaks", "Jabaroot")
    
    print("[*] Lancement du mapping LLM pour chaque jour...")
    if os.path.exists(jabaroot_dir):
        for date_folder in os.listdir(jabaroot_dir):
            leaks_file = os.path.join(jabaroot_dir, date_folder, "leaks.json")
            if os.path.exists(leaks_file):
                await agent.process_daily_leaks(leaks_file, analyzer)
                
    # 2. Generate PDF Reports
    if not os.path.exists(intel_file):
        print("[!] Fichier d'intelligence introuvable.")
        return
        
    try:
        with open(intel_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        print(f"\n[*] Génération des rapports PDF pour {len(data)} incidents...")
        
        reporter = LeakReporter(intel_file)
        reports_dir = os.path.join(INTEL_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        for leak in data:
            severity = leak.get("leak_metadata", {}).get("severity", "LOW").upper()
            intel_id = leak.get("intel_id")
            
            if severity in ["HIGH", "CRITICAL"]:
                pdf_path = os.path.join(reports_dir, f"{intel_id}.pdf")
                safe_id = str(intel_id).encode('ascii', 'replace').decode('ascii')
                print(f"  - Création PDF: {safe_id} ({severity})")
                reporter.generate_pdf_bulletin(intel_id, pdf_path)
                
        print("\n[+] Opération terminée avec succès !")
    except Exception as e:
        import traceback
        print(f"[ERROR] Erreur finale: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(run_pipeline())
