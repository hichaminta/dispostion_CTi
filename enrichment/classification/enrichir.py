import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import json
import os
import logging
import argparse
from classifier import ThreatClassifier
from scorer import PriorityScorer
from reliability import SourceReliability
try:
    from mitre_mapper import map_record
except ImportError:
    map_record = None

logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Intelligence_Orchestrator")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENRICHMENT_DIR = os.path.join(BASE_DIR, "output_enrichment")


class IntelligenceOrchestrator:
    """Orchestre classification, fiabilité et scoring sur tous les fichiers enrichis."""

    def __init__(self, enrichment_dir: str):
        self.enrichment_dir = enrichment_dir

    def run(self, source_filter=None, skip_enriched=False):
        if not os.path.exists(self.enrichment_dir):
            logger.error(f"Répertoire introuvable : {self.enrichment_dir}")
            return

        json_files = [f for f in os.listdir(self.enrichment_dir) if f.endswith("_enriched.json")]
        if source_filter:
            json_files = [f for f in json_files if source_filter.lower() in f.lower()]

        if not json_files:
            logger.warning("Aucun fichier trouvé.")
            return

        stats = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for filename in json_files:
            filepath = os.path.join(self.enrichment_dir, filename)
            logger.info(f"Traitement : {filename}")

            with open(filepath, "r", encoding="utf-8") as f:
                records = json.load(f)

            modified = False
            for record in records:
                # Skip si déjà traité et --skip-enriched activé
                if skip_enriched and "soc_enriched" in record.get("tags", []):
                    continue

                stats["total"] += 1

                modified_record = False

                # 1. Classification
                if not record.get("passer_par_callasifcation"):
                    threat_type = ThreatClassifier.infer_threat_type(record, filename)
                    attack_type = ThreatClassifier.classify_attack_type(record, threat_type)
                    record["threat_type"] = threat_type   # malware | phishing | vulnerability | suspicious
                    record["attack_type"] = attack_type   # Botnet | RAT | Stealer | RCE | Credential | ...
                    record["passer_par_callasifcation"] = 1
                    modified_record = True
                else:
                    threat_type = record.get("threat_type", "suspicious")

                # 2. Fiabilité source / Reliability
                if not record.get("paser_reliablity"):
                    source_key = filename.split("_")[0]
                    SourceReliability.apply_reliability_tag(record, source_key)
                    record["confidence_label"] = ThreatClassifier.get_confidence_label(
                        record.get("source_confidence", 50)
                    )
                    record["paser_reliablity"] = 1
                    modified_record = True

                # 2.5 Mapping MITRE ATT&CK
                if map_record and not record.get("passer_par_mittre_attck"):
                    if map_record(record):
                        record["passer_par_mittre_attck"] = 1
                        modified_record = True

                # 3. Scoring priorité + risque additif
                if not record.get("passser_par_scoring"):
                    priority, action = PriorityScorer.calculate_priority(record, threat_type)
                    record["priority_score"]      = priority   # CRITICAL | HIGH | MEDIUM | LOW
                    record["soc_action"]          = action     # escalate | investigate | monitor | block | monitor_quiet
                    record["risk_score_additive"] = PriorityScorer.calculate_additive_risk(record)
                    
                    # Score par IOC individuel
                    src_conf = record.get("source_confidence", 50)
                    for ioc in record.get("iocs", []):
                        ioc["risk_score"] = PriorityScorer.calculate_ioc_risk(ioc, src_conf)
                        # Action simplifiée par IOC
                        if ioc["risk_score"] >= 70: ioc["soc_action"] = "investigate"
                        elif ioc["risk_score"] >= 40: ioc["soc_action"] = "monitor"
                        else: ioc["soc_action"] = "monitor_quiet"

                    record["passser_par_scoring"] = 1
                    modified_record = True
                else:
                    priority = record.get("priority_score", "LOW")

                # 4. Marquage final
                if modified_record:
                    record.setdefault("tags", [])
                    if "soc_enriched" not in record["tags"]:
                        record["tags"].append("soc_enriched")
                    stats[priority] = stats.get(priority, 0) + 1
                    modified = True

            if modified:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=4, ensure_ascii=False)
                logger.info(f"[OK] {filename} sauvegardé.")

        # Résumé
        logger.info("=" * 55)
        logger.info(f"  TOTAL     : {stats['total']} records traités")
        logger.info(f"  CRITICAL  : {stats.get('CRITICAL', 0)}")
        logger.info(f"  HIGH      : {stats.get('HIGH', 0)}")
        logger.info(f"  MEDIUM    : {stats.get('MEDIUM', 0)}")
        logger.info(f"  LOW       : {stats.get('LOW', 0)}")
        logger.info("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI Intelligence Orchestrator")
    parser.add_argument("-s", "--source",        help="Filtrer par source (ex: feodotracker)")
    parser.add_argument("--skip-enriched",       action="store_true", help="Ignorer les records déjà traités")
    parser.add_argument("-d", "--dir",           help="Répertoire custom (override ENRICHMENT_DIR)")
    args = parser.parse_args()

    enrichment_dir = args.dir if args.dir else ENRICHMENT_DIR
    orch = IntelligenceOrchestrator(enrichment_dir)
    orch.run(source_filter=args.source, skip_enriched=args.skip_enriched)