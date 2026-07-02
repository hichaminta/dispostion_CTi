import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import json
import os
import logging

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DemoSelectiveEnrichment")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "Pipeline_cti/global_output/output_enrichment")
ALIENVAULT_FILE = os.path.join(OUTPUT_DIR, "alienvault_enriched.json")

def score_record(record):
    """
    Calcule un score d'enrichissement pour un enregistrement.
    Plus le score est Ã©levÃ©, plus l'enregistrement est complet.
    """
    score = 0
    
    # 1. IOC Enrichment (VirusTotal)
    iocs = record.get("iocs", [])
    for ioc in iocs:
        enrichment = ioc.get("ioc_enrichment", {})
        if enrichment.get("passer_par_virustotal") == 1:
            score += 10
        if "vt_malicious_count" in enrichment:
            score += 5
            
    # 2. NLP Analysis
    attributes = record.get("attributes", {})
    nlp = attributes.get("nlp_analysis", {})
    if nlp:
        score += 20
        if nlp.get("vendors"): score += 5
        if nlp.get("products"): score += 5
        
    # 3. MITRE ATT&CK
    mitre = record.get("mitre_attack", [])
    if mitre:
        score += 15
        score += len(mitre) * 2
        
    # 4. Description length (indication of richness)
    description = record.get("description", "")
    if len(description) > 100:
        score += 5
        
    return score

def filter_alienvault_for_demo():
    if not os.path.exists(ALIENVAULT_FILE):
        logger.warning(f"Fichier introuvable : {ALIENVAULT_FILE}")
        return

    try:
        with open(ALIENVAULT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            logger.warning("Les donnÃ©es ne sont pas une liste.")
            return

        if len(data) <= 3:
            logger.info("DÃ©jÃ  3 enregistrements ou moins, aucun filtrage nÃ©cessaire.")
            return

        # Calculer les scores et trier
        scored_records = []
        for record in data:
            score = score_record(record)
            scored_records.append((score, record))
            
        # Trier par score dÃ©croissant
        scored_records.sort(key=lambda x: x[0], reverse=True)
        
        # Garder les 3 meilleurs
        best_records = [record for score, record in scored_records[:3]]
        
        # Sauvegarder
        with open(ALIENVAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(best_records, f, indent=4)
            
        logger.info(f"Demo filter: {len(data)} -> 3 enregistrements les plus enrichis conservÃ©s dans {ALIENVAULT_FILE}")
        
    except Exception as e:
        logger.error(f"Erreur lors du filtrage dÃ©mo : {e}")

if __name__ == "__main__":
    filter_alienvault_for_demo()
