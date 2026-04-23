import os
import json
import logging
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
    Client pour l'intégration avec l'API MISP simplifié (sans tracking local).
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
    # Gestion des événements MISP par source
    # ------------------------------------------------------------------

    def _get_or_create_event_by_info(self, info_string):
        """
        Recherche un événement existant par son champ 'info' exact ou en crée un nouveau.
        Ceci permet d'avoir un événement unique par enregistrement (record_id).
        """
        if not self.misp:
            return None

        try:
            # Recherche exacte sur le champ info
            search_result = self.misp.search(
                controller='events',
                info=info_string
            )
            if search_result and len(search_result) > 0:
                # Vérification de correspondance exacte pour éviter les correspondances partielles
                for res in search_result:
                    if res["Event"]["info"] == info_string:
                        return res["Event"]["uuid"]
        except Exception as e:
            logger.warning(f"Erreur recherche événement '{info_string}': {e}")

        # Créer un nouvel événement si non trouvé
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

            new_uuid = result["Event"]["uuid"]
            logger.info(f"Nouvel événement créé : {info_string} (UUID: {new_uuid})")
            return new_uuid
        except Exception as e:
            logger.error(f"Exception lors de la création d'événement '{info_string}': {e}")
            return None

    # ------------------------------------------------------------------
    # Push d'un fichier JSON vers MISP
    # ------------------------------------------------------------------

    def push_event_file(self, json_file_path):
        """
        Pousse les attributs d'un fichier JSON vers l'événement de la source
        correspondante dans MISP. Version simplifiée : pas de tracking.
        """
        if not self.misp:
            return False

        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Impossible de lire {json_file_path}: {e}")
            return False

        # Normalisation : on travaille toujours avec une liste
        events_to_process = data if isinstance(data, list) else [data]
        if not events_to_process:
            return False

        added_count = 0

        for item in events_to_process:
            event_data = item.get("Event")
            if not event_data:
                continue

            # Utilisation du champ 'info' complet (Source - Date) pour permettre un nouvel événement par jour
            info_string = event_data.get("info", "CTI Export")
            event_uuid = self._get_or_create_event_by_info(info_string)
            
            if not event_uuid:
                continue

            # Traitement des attributs directs uniquement (pas de "normalisation" interne complexe)
            attributes = event_data.get("Attribute") or event_data.get("attributes") or []
            
            for attr_data in attributes:
                try:
                    res = self.misp.add_attribute(event_uuid, {
                        "type": attr_data["type"],
                        "value": attr_data["value"],
                        "comment": attr_data.get("comment", ""),
                        "to_ids": attr_data.get("to_ids", True)
                    })
                    
                    if isinstance(res, dict) and "errors" not in res:
                        # Ajout des tags sur l'attribut s'ils existent
                        attr_uuid = res["Attribute"]["uuid"]
                        for tag in attr_data.get("Tag", []):
                            self.misp.tag(attr_uuid, tag["name"])
                        added_count += 1
                    elif isinstance(res, dict) and "errors" in res:
                        err_msg = str(res['errors'])
                        if 'A similar attribute already exists' in err_msg:
                            logger.info(f"Sauté : {attr_data['value']} (existe déjà)")
                        else:
                            logger.error(f"Erreur ajout attribut : {res['errors']}")
                except Exception as e:
                    logger.error(f"Exception ajout attribut : {e}")

        if added_count > 0:
            logger.info(f"Synchronisation terminée : +{added_count} indicateurs ajoutés.")
        
        return True

    # ------------------------------------------------------------------
    # Push du dernier run
    # ------------------------------------------------------------------

    def push_latest(self, source_filter=None):
        """
        Pousse tous les fichiers JSON du dernier run disponible dans output_misp/.
        """
        misp_output = os.path.join(BASE_DIR, "output_misp")
        if not os.path.exists(misp_output):
            logger.error(f"Dossier output_misp non trouvé : {misp_output}")
            return

        runs = [
            d for d in os.listdir(misp_output)
            if d.startswith("misp_run_") or d.startswith("run_")
        ]
        if not runs:
            logger.warning("Aucun run MISP trouvé dans output_misp/.")
            return

        latest_run = os.path.join(misp_output, sorted(runs)[-1])
        logger.info(f"Synchronisation du run : {latest_run}")

        for root, dirs, files in os.walk(latest_run):
            for file in files:
                if not file.endswith(".json"):
                    continue
                if source_filter and (
                    source_filter.lower() not in file.lower()
                    and source_filter.lower() not in root.lower()
                ):
                    continue
                file_path = os.path.join(root, file)
                logger.info(f"Traitement : {file_path}")
                self.push_event_file(file_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Synchronise les fichiers CTI JSON vers une instance MISP."
    )
    parser.add_argument(
        "-f", "--file",
        help="Pousser un fichier JSON spécifique vers MISP."
    )
    parser.add_argument(
        "-s", "--source",
        help="Pousser uniquement une source particulière du dernier run."
    )
    args = parser.parse_args()

    client = MISPClient()

    if not client.misp:
        logger.error("Connexion MISP échouée. Vérifiez MISP_URL et MISP_KEY dans .env")
        exit(1)

    if args.file:
        success = client.push_event_file(args.file)
        exit(0 if success else 1)
    else:
        client.push_latest(source_filter=args.source)