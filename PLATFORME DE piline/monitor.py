import os
import json
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Chemins
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_DIR = os.path.join(BASE_DIR, "Sources_data")
OUTPUT_STATUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "status.json")

def fast_count_records(file_path):
    """Compte le nombre de records sans charger tout le JSON (très rapide)."""
    if not os.path.exists(file_path):
        return 0
    
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                # Patterns communs pour détecter un objet JSON dans une liste
                if line.strip() == "{" or line.lstrip().startswith('{"') or (line.startswith("    {") and not line.strip() == "{"):
                    # On cherche des clés d'identifiants
                    if any(key in line for key in ['"id":', '"ioc":', '"cve_id":', '"id_cve":', '"impact":']):
                         count += 1
                elif any(key in line for key in ['"id":', '"ioc":', '"cve_id":']):
                    count += 1
        
        # Fallback pour petits fichiers
        if count == 0 and os.path.getsize(file_path) > 2:
             try:
                 with open(file_path, "r", encoding="utf-8") as f:
                     data = json.load(f)
                     return len(data) if isinstance(data, (list, dict)) else 0
             except: return 0
        return count
    except Exception as e:
        logging.error(f"Erreur comptage rapide pour {file_path}: {e}")
        return 0

def get_source_data_file(source_path):
    """Trouve le fichier de données JSON principal (le plus gros JSON)."""
    json_files = []
    for f in os.listdir(source_path):
        if f.endswith(".json") and f != "tracking.json" and not f.endswith(".tmp"):
            full_path = os.path.join(source_path, f)
            json_files.append((full_path, os.path.getsize(full_path)))
    if not json_files: return None
    json_files.sort(key=lambda x: x[1], reverse=True)
    return json_files[0][0]

def determine_type(source_name, data_file):
    """Détermine si la source est CVE ou IOC basé sur le nom."""
    name_lower = source_name.lower()
    file_lower = os.path.basename(data_file).lower() if data_file else ""
    if any(k in name_lower for k in ["cve", "nvd", "vuln"]) or any(k in file_lower for k in ["cve", "nvd"]):
        return "CVE"
    return "IOC"

def main():
    if not os.path.exists(SOURCES_DIR):
        logging.error(f"Dossier Sources_data non trouvé à {SOURCES_DIR}")
        return

    sources_info = []
    total_iocs = 0
    total_cves = 0
    
    source_dirs = [s for s in os.listdir(SOURCES_DIR) if os.path.isdir(os.path.join(SOURCES_DIR, s))]
    print(f"Analyse de {len(source_dirs)} sources en cours (Mode CVE vs IOC)...")

    for i, source_name in enumerate(source_dirs):
        source_path = os.path.join(SOURCES_DIR, source_name)
        tracking_file = os.path.join(source_path, "tracking.json")
        data_file = get_source_data_file(source_path)
        
        source_type = determine_type(source_name, data_file)

        # Tracking info
        last_sync = "Jamais"
        latest_modified = "Inconnu"
        status = "Inactif"
        if os.path.exists(tracking_file):
            try:
                with open(tracking_file, "r", encoding="utf-8") as f:
                    tracking = json.load(f)
                    
                    # Standard keys
                    last_sync = tracking.get("last_run", tracking.get("last_sync_success", "Jamais"))
                    latest_modified = tracking.get("latest_modified", "Inconnu")
                    earliest_modified = tracking.get("earliest_modified", "Inconnu")
                    last_sync_attempt = tracking.get("last_sync_attempt", "N/A")
                    status = "Actif"
            except:
                status = "Erreur Tracking"

        # Fallback pour dates si manquantes
        if latest_modified == "Inconnu" and data_file:
            try:
                mtime = os.path.getmtime(data_file)
                latest_modified = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            except: pass

        # Counting
        print(f"[{i+1}/{len(source_dirs)}] ({source_type}) {source_name}...")
        records = fast_count_records(data_file) if data_file else 0
        
        if source_type == "IOC": total_iocs += records
        else: total_cves += records

        sources_info.append({
            "name": source_name,
            "type": source_type,
            "status": status,
            "last_sync": last_sync,
            "latest_modified": latest_modified,
            "earliest_modified": earliest_modified,
            "last_sync_attempt": last_sync_attempt,
            "records": records,
            "data_file": os.path.basename(data_file) if data_file else None
        })

    # Dashboard Output
    dashboard_data = {
        "last_updated": datetime.now().isoformat(),
        "total_sources": len(sources_info),
        "total_iocs": total_iocs,
        "total_cves": total_cves,
        "sources": sources_info
    }

    with open(OUTPUT_STATUS, "w", encoding="utf-8") as f:
        json.dump(dashboard_data, f, indent=4, ensure_ascii=False)

    print("-" * 30)
    print(f"Terminé ! Status généré dans status.json")
    print(f"IOCs: {total_iocs} | CVEs: {total_cves}")

if __name__ == "__main__":
    main()
