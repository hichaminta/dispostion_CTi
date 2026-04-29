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
    # Gestion des événements MISP
    # ------------------------------------------------------------------

    def _get_or_create_event_by_info(self, info_string):
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
        event.threat_level_id = 2
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
    # Push d'un fichier JSON
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
        Parcourt output_misp/ et pousse tous les fichiers non encore intégrés.
        """
        misp_output = os.path.join(BASE_DIR, "output_misp")
        if not os.path.exists(misp_output):
            logger.error(f"Dossier output_misp absent : {misp_output}")
            return

        for root, dirs, files in os.walk(misp_output):
            for file in files:
                if not file.endswith(".json"):
                    continue
                
                # Filtrer par source si demandé
                if source_filter and source_filter.lower() not in root.lower() and source_filter.lower() not in file.lower():
                    continue
                
                file_path = os.path.join(root, file)
                self.push_event_file(file_path)


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