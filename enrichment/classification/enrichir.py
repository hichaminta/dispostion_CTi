
import json
import os
import logging
import argparse
from classifier import ThreatClassifier
from scorer import PriorityScorer
from reliability import SourceReliability

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Intelligence_Orchestrator")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")

class IntelligenceOrchestrator:
    """Orchestrates classification, reliability, and scoring."""
    
    def __init__(self, enrichment_dir):
        self.enrichment_dir = enrichment_dir

    def run(self, source_filter=None, skip_enriched=False):
        if not os.path.exists(self.enrichment_dir):
            logger.error(f"Directory not found: {self.enrichment_dir}")
            return

        json_files = [f for f in os.listdir(self.enrichment_dir) if f.endswith("_enriched.json")]
        if source_filter:
            json_files = [f for f in json_files if source_filter.lower() in f.lower()]

        for filename in json_files:
            filepath = os.path.join(self.enrichment_dir, filename)
            logger.info(f"Processing {filename}...")
            
            with open(filepath, 'r', encoding='utf-8') as f:
                records = json.load(f)

            modified = False
            for record in records:
                if skip_enriched and "soc_enriched" in record.get("tags", []):
                    continue

                # 1. Classification
                threat_type = ThreatClassifier.infer_threat_type(record, filename)
                record["attack_type"] = ThreatClassifier.classify_attack_type(record, threat_type)
                
                # 2. Reliability (Confidence)
                source_key = filename.split('_')[0]
                SourceReliability.apply_reliability_tag(record, source_key)
                
                # 3. Scoring
                priority, action = PriorityScorer.calculate_priority(record, threat_type)
                record["priority_score"] = priority
                record["soc_action"] = action
                record["risk_score_additive"] = PriorityScorer.calculate_additive_risk(record)
                
                # Final Mark
                if "soc_enriched" not in record.get("tags", []):
                    record.setdefault("tags", []).append("soc_enriched")
                modified = True

            if modified:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(records, f, indent=4, ensure_ascii=False)
                logger.info(f"[OK] {filename} fully classified and scored.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--source")
    parser.add_argument("--skip-enriched", action="store_true")
    args = parser.parse_args()
    
    orch = IntelligenceOrchestrator(ENRICHMENT_DIR)
    orch.run(source_filter=args.source, skip_enriched=args.skip_enriched)
