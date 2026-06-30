import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import logging
import spacy
import re
from datetime import datetime

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CVENLPEnrichment")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "global_output", "sources")


TRACKING_DIR = os.path.join(BASE_DIR, "tracking", "tracking_enrichment")

def get_tracking_file(source):
    return os.path.join(TRACKING_DIR, f"{source}_tracking.json")

def load_source_tracking(source):
    if not os.path.exists(TRACKING_DIR):
        os.makedirs(TRACKING_DIR)
    path = get_tracking_file(source)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_source_tracking(source, data):
    path = get_tracking_file(source)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# Chargement du modèle spaCy
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("Modèle spaCy 'en_core_web_sm' chargé avec succès.")
except Exception as e:
    logger.error(f"Erreur lors du chargement de spaCy : {e}")
    logger.info("Tentative de téléchargement du modèle...")
    os.system("python -m spacy download en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

def extract_entities(text):
    """
    Extrait les entités pertinentes d'une description CVE via spaCy et regex.
    """
    if not text or len(text) < 10:
        return None
    
    doc = nlp(text)
    entities = {
        "vendors": [],
        "products": [],
        "versions": [],
        "platforms": []
    }
    
    # Extraction via spaCy NER
    for ent in doc.ents:
        if ent.label_ == "ORG":
            entities["vendors"].append(ent.text)
        elif ent.label_ == "PRODUCT":
            entities["products"].append(ent.text)
        elif ent.label_ == "GPE":
            entities["platforms"].append(ent.text)
            
    # Extraction complémentaire via Regex (pour les versions souvent manquées par spaCy)
    # Cherche des patterns comme v1.2, version 2.0, 5.x, etc.
    version_patterns = [
        r"(?:v|version\s|build\s)([0-9]+(?:\.[0-9x]+)+)",
        r"([0-9]+(?:\.[0-9x]+)+)"
    ]
    
    for pattern in version_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            v = match.group(0).strip()
            if v not in entities["versions"] and len(v) > 1:
                entities["versions"].append(v)
                
    # Nettoyage des doublons
    for key in entities:
        entities[key] = list(set(entities[key]))
        
    return entities

def process_files():

    import glob
    json_files = glob.glob(os.path.join(GLOBAL_SOURCES_DIR, "*", "enrichment", "*_enriched.json"))
    
    for filepath in json_files:
        filename = os.path.basename(filepath)
        source = os.path.basename(os.path.dirname(os.path.dirname(filepath)))
        logger.info(f"Analyse NLP du fichier : {filename}")
        
        # Tracking logic
        source_data = load_source_tracking(source)
        if "nlp_enrichment_cve" not in source_data:
            source_data["nlp_enrichment_cve"] = {
                "last_run": None,
                "files_processed": [],
                "entities_extracted": 0
            }
        
        # if filename in source_data["nlp"]["files_processed"]:
        #     logger.info(f"Skipping {filename} (already processed for NLP)")
        #     continue

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Erreur lecture {filename}: {e}")
            continue

        modified = False
        for record in data:
            # On cherche les CVEs dans le record
            cves = record.get("cves", [])
            description = record.get("description", "")
            
            # Si pas de description globale, on regarde dans les CVEs
            if not description and cves:
                for cve in cves:
                    if cve.get("ioc_enrichment", {}).get("description"):
                        description = cve["ioc_enrichment"]["description"]
                        break
            
            if description:
                # Si on n'a pas encore fait l'analyse NLP ou si elle est vide
                current_nlp = record.get("attributes", {}).get("nlp_analysis")
                if not current_nlp:
                    entities = extract_entities(description)
                    if entities:
                        if "attributes" not in record:
                            record["attributes"] = {}
                        
                        entities["tlp"] = "TLP:CLEAR"
                        entities["nlp_enriched_at"] = datetime.now().isoformat()
                        record["attributes"]["nlp_analysis"] = entities
                        
                        # Mettre à jour également dans les objets CVE pour la cohérence
                        for cve in cves:
                            if "ioc_enrichment" not in cve:
                                cve["ioc_enrichment"] = {}
                            cve["ioc_enrichment"]["nlp_extracted"] = entities
                            
                        modified = True

        # Update tracking always
        source_data["nlp_enrichment_cve"]["last_run"] = datetime.now().isoformat()
        if filename not in source_data["nlp_enrichment_cve"]["files_processed"]:
            source_data["nlp_enrichment_cve"]["files_processed"].append(filename)
        
        # Count total NLP-enriched records
        nlp_count = sum(1 for r in data if r.get("attributes", {}).get("nlp_analysis"))
        source_data["nlp_enrichment_cve"]["entities_extracted"] = nlp_count
        save_source_tracking(source, source_data)

        if modified:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                logger.info(f"Fichier {filename} mis à jour avec l'analyse NLP.")
            except Exception as e:
                logger.error(f"Erreur écriture {filename}: {e}")
        else:
            logger.info(f"Aucune nouvelle analyse NLP nécessaire pour {filename}.")

if __name__ == "__main__":
    process_files()
