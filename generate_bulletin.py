import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Add leak_data_integration to path
sys.path.insert(0, os.path.join(os.getcwd(), "leak_data_integration"))

from core.reporter import LeakReporter

def main():
    load_dotenv()
    
    # Configuration
    start_date = os.getenv("LEAK_START_DATE", "2026-04-26")
    end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize reporter
    intel_file = os.path.join("leak_data_integration", "results", "leaks_intel.json")
    reporter = LeakReporter(intel_file)
    
    # Generate text summary
    print(f"Génération du bulletin de sécurité depuis {start_date} 00:00...")
    summary = reporter.generate_summary(start_date, end_date)
    
    # Display in terminal
    print("\n" + summary)
    
    # Save text report
    report_name = f"bulletin_securite_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = os.path.join("reports", report_name)
    
    if reporter.save_report(summary, report_path):
        print(f"\n[SUCCESS] Rapport texte enregistré dans : {report_path}")
    else:
        print("\n[ERROR] Échec de l'enregistrement du rapport texte.")

    # Generate individual PDF bulletins for the found leaks
    try:
        import json
        with open(intel_file, 'r', encoding='utf-8') as f:
            intel_data = json.load(f)
        
        from datetime import datetime
        start_dt = datetime.strptime(f"{start_date} 00:00:00", "%Y-%m-%d %H:%M:%S")
        
        pdf_count = 0
        for leak in intel_data:
            leak_dt = datetime.fromisoformat(leak["timestamp"])
            if leak_dt >= start_dt:
                intel_id = leak["intel_id"]
                pdf_path = os.path.join("reports", f"bulletin_{intel_id}.pdf")
                if reporter.generate_pdf_bulletin(intel_id, pdf_path):
                    print(f"[PDF] Bulletin généré pour {intel_id} -> {pdf_path}")
                    pdf_count += 1
        
        if pdf_count > 0:
            print(f"\n[SUCCESS] {pdf_count} bulletins PDF générés avec le style BlueSec.")
            
    except Exception as e:
        print(f"\n[ERROR] Erreur lors de la génération des PDFs : {e}")

if __name__ == "__main__":
    main()
