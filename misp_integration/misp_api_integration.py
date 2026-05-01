import os
import json
import logging
from datetime import datetime
from pymisp import PyMISP, MISPEvent
from dotenv import load_dotenv

# Charge les variables d'environnement (.env)
load_dotenv()

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MISP_Integration")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class MISPClient:
    """
    Client pour l'intégration avec l'API MISP avec tracking intégré dans les fichiers JSON.
    """

    def __init__(self):
        self.url = os.getenv("MISP_URL")
        self.key = os.getenv("MISP_KEY")
        self.verifycert = os.getenv("MISP_VERIFYCERT", "False").lower() == "true"
        
        if not self.url or not self.key or "YOUR_MISP" in self.key:
            logger.error("MISP_URL ou MISP_KEY non configuré dans le fichier .env")
            self.misp = None
        else:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                self.misp = PyMISP(self.url, self.key, self.verifycert, debug=False)
                logger.info(f"Connecté avec succès à MISP : {self.url}")
            except Exception as e:
                logger.error(f"Erreur de connexion à MISP : {e}")
                self.misp = None

    # ------------------------------------------------------------------
    # Mappage SOC -> MISP
    # ------------------------------------------------------------------

    def _get_threat_level(self, priority):
        """Mappe le priority_score SOC (LOW/MEDIUM/HIGH/CRITICAL) vers MISP (1-4)."""
        p = str(priority).upper()
        mapping = {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3
        }
        return mapping.get(p, 4)

    # ------------------------------------------------------------------
    # Gestion des événements MISP
    # ------------------------------------------------------------------

    def _get_or_create_event_by_info(self, info_string, risk_level="low"):
        """
        Recherche un événement existant par son champ 'info' ou en crée un.
        """
        if not self.misp:
            return None

        try:
            search_result = self.misp.search(controller='events', info=info_string)
            if search_result and len(search_result) > 0:
                for res in search_result:
                    if res["Event"]["info"] == info_string:
                        return res["Event"]["uuid"]
        except Exception as e:
            logger.warning(f"Erreur recherche événement '{info_string}': {e}")

        event = MISPEvent()
        event.info = info_string
        event.distribution = 0
        event.threat_level_id = self._get_threat_level(risk_level)
        event.analysis = 0

        try:
            result = self.misp.add_event(event)
            if "errors" in result:
                logger.error(f"Erreur création événement '{info_string}': {result['errors']}")
                return None
            return result["Event"]["uuid"]
        except Exception as e:
            logger.error(f"Exception création événement '{info_string}': {e}")
            return None

    # ------------------------------------------------------------------
    # Push des événements corrélés (Nouveau format)
    # ------------------------------------------------------------------

    def push_correlated_file(self, json_file_path):
        """
        Pousse les événements d'un fichier corrélé (format SOC) vers MISP.
        """
        if not self.misp:
            return False

        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                events_data = json.load(f)
        except Exception as e:
            logger.error(f"Impossible de lire {json_file_path}: {e}")
            return False

        file_modified = False
        type_mapping = {
            "ip": "ip-dst", "url": "url", "domain": "domain", "hostname": "hostname",
            "sha256": "sha256", "md5": "md5", "sha1": "sha1", "cve": "vulnerability"
        }

        for event_item in events_data:
            # Ignorer les événements de vulnérabilité (CVE) comme demandé
            if event_item.get("event_type") == "vulnerability":
                continue

            info_name = event_item.get("event_name")
            priority = event_item.get("priority_score", "LOW")
            
            event_uuid = self._get_or_create_event_by_info(info_name, priority)
            if not event_uuid: continue

            for ioc in event_item.get("iocs", []):
                if ioc.get("integre_par_misp") == 1: continue

                misp_type = type_mapping.get(ioc["type"].lower(), ioc["type"])
                
                try:
                    # Construction du commentaire SOC enrichi
                    comment = f"Priority: {event_item.get('priority_score')} | Action: {event_item.get('soc_action')}"
                    if event_item.get("attack_type") and event_item.get("attack_type") != "Unknown":
                        comment += f" | Type: {event_item['attack_type']}"
                    if event_item.get("threat_context") and event_item.get("threat_context") != "none":
                        comment += f" | Context: {event_item['threat_context']}"
                    if event_item.get("epss"):
                        comment += f" | EPSS: {event_item['epss']}"

                    # Nettoyage des IPs avec port (ex: 1.1.1.1:80 -> 1.1.1.1)
                    val = ioc["value"]
                    if misp_type in ["ip-src", "ip-dst", "ip-src/ip-dst"] and ":" in str(val):
                        val = str(val).split(":")[0]

                    res = self.misp.add_attribute(event_uuid, {
                        "type": misp_type,
                        "value": val,
                        "comment": comment,
                        "to_ids": True
                    })
                    
                    if isinstance(res, dict) and "errors" not in res:
                        attr_uuid = res["Attribute"]["uuid"]
                        # Tags globaux et MITRE
                        for tag in event_item.get("tags", []):
                            self.misp.tag(attr_uuid, tag)
                        for tech in event_item.get("mitre_techniques", []):
                            if tech != "Unknown":
                                self.misp.tag(attr_uuid, f"mitre-attack:technique=\"{tech}\"")
                        
                        logger.info(f"Poussé (Corrélé) : {ioc['value']}")
                        ioc["integre_par_misp"] = 1
                        file_modified = True
                    elif isinstance(res, dict) and "errors" in res:
                        if 'A similar attribute already exists' in str(res['errors']):
                            ioc["integre_par_misp"] = 1
                            file_modified = True
                except Exception as e:
                    logger.error(f"Exception push corrélé pour {ioc['value']}: {e}")

        if file_modified:
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(events_data, f, indent=4)
        return True

    # ------------------------------------------------------------------
    # Push d'un fichier JSON classique
    # ------------------------------------------------------------------

    def push_event_file(self, json_file_path):
        """
        Pousse les attributs d'un fichier JSON vers MISP avec tracking par IOC (Attribute).
        """
        if not self.misp:
            return False

        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Impossible de lire {json_file_path}: {e}")
            return False

        items = data if isinstance(data, list) else [data]
        file_modified = False

        for item in items:
            event_data = item.get("Event")
            if not event_data:
                continue
            
            info_string = event_data.get("info", "CTI Export")
            event_uuid = self._get_or_create_event_by_info(info_string)
            if not event_uuid:
                continue

            attributes = event_data.get("Attribute") or event_data.get("attributes") or []
            
            for attr_data in attributes:
                # Vérifier si cet IOC spécifique est déjà marqué comme intégré
                if attr_data.get("integre_par_misp") == 1:
                    continue

                try:
                    res = self.misp.add_attribute(event_uuid, {
                        "type": attr_data["type"],
                        "value": attr_data["value"],
                        "comment": attr_data.get("comment", ""),
                        "to_ids": attr_data.get("to_ids", True)
                    })
                    
                    if isinstance(res, dict) and "errors" not in res:
                        attr_uuid = res["Attribute"]["uuid"]
                        for tag in attr_data.get("Tag", []):
                            self.misp.tag(attr_uuid, tag["name"])
                        logger.info(f"Poussé : {attr_data['value']}")
                        attr_data["integre_par_misp"] = 1
                        file_modified = True
                    elif isinstance(res, dict) and "errors" in res:
                        err_msg = str(res['errors'])
                        # Si déjà présent ou invalide, on marque quand même comme traité pour ne pas boucler dessus
                        if 'A similar attribute already exists' in err_msg or 'Invalid CIDR' in err_msg:
                            logger.info(f"Sauté (déjà présent ou invalide) : {attr_data['value']}")
                            attr_data["integre_par_misp"] = 1
                            file_modified = True
                        else:
                            logger.error(f"Erreur MISP pour {attr_data['value']}: {res['errors']}")
                except Exception as e:
                    logger.error(f"Exception push pour {attr_data['value']}: {e}")

        if file_modified:
            try:
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(items, f, indent=2)
                logger.info(f"Fichier mis à jour avec les nouveaux status IOC : {json_file_path}")
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde du fichier : {e}")

        return True

    def push_all(self, source_filter=None):
        """
        Parcourt uniquement output_correlation/ pour pousser les fichiers consolidés.
        L'ancien dossier output_misp/ est ignoré pour éviter les doublons et les CVE non filtrés.
        """
        # 1. Dossier Corrélation (Prioritaire et Unique)
        corr_dir = os.path.join(BASE_DIR, "output_correlation")
        if os.path.exists(corr_dir):
            for f in os.listdir(corr_dir):
                if f.endswith(".json") and "soc_enriched" in f:
                    logger.info(f"Synchronisation du fichier enrichi : {f}")
                    self.push_correlated_file(os.path.join(corr_dir, f))

        # 2. Dossier MISP (Désactivé pour éviter les doublons et CVE)
        # misp_output = os.path.join(BASE_DIR, "output_misp")
        # if os.path.exists(misp_output):
        #     for root, dirs, files in os.walk(misp_output):
        #         for file in files:
        #             if not file.endswith(".json"): continue
        #             if source_filter and source_filter.lower() not in root.lower() and source_filter.lower() not in file.lower():
        #                 continue
        #             self.push_event_file(os.path.join(root, file))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synchronisation vers MISP")
    parser.add_argument("-f", "--file", help="Fichier JSON spécifique")
    parser.add_argument("-s", "--source", help="Filtrer par source")
    args = parser.parse_args()

    client = MISPClient()
    if not client.misp:
        exit(1)

    if args.file:
        client.push_event_file(args.file)
    else:
        client.push_all(source_filter=args.source)