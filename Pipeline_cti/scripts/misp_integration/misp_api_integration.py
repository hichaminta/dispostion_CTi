import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import logging
import uuid
from datetime import datetime
from pymisp import PyMISP, MISPEvent
from dotenv import load_dotenv

# Charge les variables d'environnement (.env)
load_dotenv()

# Configuration du logging
logging.basicConfig(encoding="utf-8", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MISP_Integration")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


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

        self.tracking_file = os.path.join(BASE_DIR, "tracking", "misp_tracking.json")

    def _load_tracking(self):
        if os.path.exists(self.tracking_file):
            try:
                with open(self.tracking_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_tracking(self, tracking_data):
        with open(self.tracking_file, "w") as f:
            json.dump(tracking_data, f, indent=4)

    def _load_stix_tracking(self):
        """Charge le tracking STIX pour la détection de doublons par report."""
        stix_tracking_file = os.path.join(BASE_DIR, "tracking", "stix_tracking.json")
        if os.path.exists(stix_tracking_file):
            try:
                with open(stix_tracking_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {"integrated_reports": {}}
        return {"integrated_reports": {}}

    def _save_stix_tracking(self, data):
        """Sauvegarde le tracking STIX."""
        stix_tracking_file = os.path.join(BASE_DIR, "tracking", "stix_tracking.json")
        with open(stix_tracking_file, "w") as f:
            json.dump(data, f, indent=4)

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

    def _get_or_create_event_by_info(self, info_string, risk_level="low", event_date=None):
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
        if event_date:
            event.date = event_date
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
        import re as _re
        _cidr_pat = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+$')
        type_mapping = {
            "ip": "ip-dst", "url": "url", "domain": "domain", "hostname": "hostname",
            "sha256": "sha256", "md5": "md5", "sha1": "sha1", "sha3_384": "sha3-384",
            "hash": "md5", "cve": "vulnerability"
        }

        for event_item in events_data:
            # Ignorer les événements de vulnérabilité (CVE) comme demandé
            if event_item.get("event_type") == "vulnerability":
                continue

            info_name = event_item.get("event_name")
            priority = event_item.get("priority_score", "LOW")
            
            # Utiliser la date de collection (first_seen) pour l'événement MISP
            first_seen = event_item.get("first_seen")
            event_date = None
            if first_seen:
                try:
                    event_date = first_seen.split('T')[0]
                except Exception:
                    pass

            event_uuid = self._get_or_create_event_by_info(info_name, priority, event_date=event_date)
            if not event_uuid: continue

            # Ajouter des tags au niveau de l'événement (Scoring et Contexte)
            integration_date = datetime.now().strftime("%Y-%m-%d")
            event_tags = [
                f"soc:integrated-at=\"{integration_date}\"",
                f"soc:priority=\"{event_item.get('priority_score', 'LOW')}\"",
                f"soc:risk-score=\"{event_item.get('risk_score', 0)}\"",
                f"soc:confidence-score=\"{event_item.get('confidence_score', 0)}\"",
                f"soc:threat-type=\"{event_item.get('threat_type', 'unknown')}\""
            ]
            if event_item.get('attack_type') and event_item['attack_type'] != 'Unknown':
                event_tags.append(f"soc:attack-type=\"{event_item['attack_type']}\"")
            
            for etag in event_tags:
                try:
                    self.misp.tag(event_uuid, etag)
                except Exception:
                    pass

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
                    # CIDRs -> network-subnet (MISP rejette ip-dst pour les CIDRs)
                    if misp_type == "ip-dst" and _cidr_pat.match(str(val)):
                        misp_type = "ip-dst"
                        comment += " | CIDR block"
                    
                    # Sécurité : Si le type est domain mais la valeur est une IP, corriger en ip-dst
                    from correlation_pre_misp import IOCCorrector
                    if misp_type == "domain" and IOCCorrector.fix_type(val, "domain") == "ip":
                        misp_type = "ip-dst"

                    res = self.misp.add_attribute(event_uuid, {
                        "type": misp_type,
                        "value": val,
                        "comment": comment,
                        "to_ids": True
                    })
                    
                    if isinstance(res, dict) and "errors" not in res:
                        attr_uuid = res["Attribute"]["uuid"]
                        # Tags globaux et MITRE
                        # Tags IOC enrichissement
                        for tag in event_item.get("tags", []):
                            if not tag.startswith("reliability:") and not tag.startswith("soc_"):
                                try: self.misp.tag(attr_uuid, tag)
                                except: pass
                        # MITRE techniques
                        for tech in event_item.get("mitre_techniques", []):
                            if tech and tech != "Unknown":
                                try: self.misp.tag(attr_uuid, f"mitre-attack:technique={tech}")
                                except: pass
                        # Tags SOC contexte
                        soc_tags = [
                            f"soc:priority={event_item.get('priority_score','LOW')}",
                            f"soc:action={event_item.get('soc_action','monitor')}",
                            f"soc:risk={event_item.get('risk_score',0)}",
                            f"soc:confidence={event_item.get('confidence_score',0)}",
                        ]
                        if event_item.get('attack_type') and event_item['attack_type'] != 'Unknown':
                            soc_tags.append(f"soc:attack-type={event_item['attack_type']}")
                        for stag in soc_tags:
                            try: self.misp.tag(attr_uuid, stag)
                            except: pass
                        
                        logger.info(f"Poussé (Corrélé) : {ioc['value']}")
                        ioc["integre_par_misp"] = 1
                        ioc["integrated_at"] = datetime.now().isoformat()
                        file_modified = True
                    elif isinstance(res, dict) and "errors" in res:
                        if 'A similar attribute already exists' in str(res['errors']):
                            ioc["integre_par_misp"] = 1
                            ioc["integrated_at"] = ioc.get("integrated_at") or datetime.now().isoformat()
                            file_modified = True
                        else:
                            logger.error(f"Erreur MISP pour {ioc['value']} ({misp_type}): {res['errors']}")
                except Exception as e:
                    logger.error(f"Exception push corrélé pour {ioc['value']}: {e}")

        if file_modified:
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(events_data, f, indent=4)
        return True

    def push_stix_bundle(self, stix_file_path):
        """
        Importe un bundle STIX 2.1 dans MISP en le découpant par Report.
        Détecte les événements/IOCs déjà intégrés pour éviter les doublons.
        Utilise un tracking persistant (stix_tracking.json) + vérification MISP.
        """
        if not self.misp:
            return False

        if not os.path.exists(stix_file_path):
            logger.error(f"Fichier STIX introuvable : {stix_file_path}")
            return False

        try:
            with open(stix_file_path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
            
            all_objects = bundle.get("objects", [])
            reports = [obj for obj in all_objects if obj.get("type") == "report"]
            other_objects = {obj["id"]: obj for obj in all_objects if obj.get("type") != "report"}

            logger.info(f"Découpage du bundle en {len(reports)} événements individuels...")

            # Charger le tracking STIX pour la détection de doublons
            stix_tracking = self._load_stix_tracking()

            success_count = 0
            skipped_count = 0

            for report in reports:
                report_name = report.get('name', 'Unnamed Event')
                report_id = report.get('id', '')

                # ── Vérification 1 : Tracking local ──
                if report_id in stix_tracking.get("integrated_reports", {}):
                    logger.info(f"[SKIP] Déjà intégré (tracking local) : {report_name}")
                    skipped_count += 1
                    continue

                # ── Vérification 2 : Événement déjà présent dans MISP ──
                already_in_misp = False
                try:
                    existing = self.misp.search(controller='events', info=report_name)
                    if existing:
                        for evt in existing:
                            if evt.get("Event", {}).get("info") == report_name:
                                logger.info(f"[SKIP] Déjà présent dans MISP : {report_name}")
                                stix_tracking.setdefault("integrated_reports", {})[report_id] = {
                                    "name": report_name,
                                    "integrated_at": datetime.now().isoformat(),
                                    "status": "already_exists_in_misp"
                                }
                                self._save_stix_tracking(stix_tracking)
                                skipped_count += 1
                                already_in_misp = True
                                break
                except Exception as e:
                    logger.warning(f"Erreur recherche événement '{report_name}': {e}")

                if already_in_misp:
                    continue

                # ── Vérification 3 : IOCs individuels déjà dans MISP ──
                # Compter les indicateurs dans ce report
                report_refs = report.get("object_refs", [])
                indicators_in_report = []
                for ref_id in report_refs:
                    obj = other_objects.get(ref_id)
                    if obj and obj.get("type") == "indicator":
                        indicators_in_report.append(obj)

                iocs_already_count = 0
                for indicator in indicators_in_report:
                    pattern = indicator.get("pattern", "")
                    # Extraire la valeur de l'IOC du pattern STIX (ex: [ipv4-addr:value = '1.2.3.4'])
                    ioc_value = self._extract_ioc_from_stix_pattern(pattern)
                    if ioc_value:
                        try:
                            search_res = self.misp.search(controller='attributes', value=ioc_value)
                            # PyMISP renvoie {'Attribute': []} si vide, dont la longueur est 1 (la clé 'Attribute')
                            if isinstance(search_res, dict) and search_res.get('Attribute'):
                                iocs_already_count += 1
                            elif isinstance(search_res, list) and len(search_res) > 0:
                                iocs_already_count += 1
                        except Exception:
                            pass

                if indicators_in_report and iocs_already_count == len(indicators_in_report):
                    logger.info(f"[SKIP] Tous les IOCs ({iocs_already_count}) déjà dans MISP : {report_name}")
                    stix_tracking.setdefault("integrated_reports", {})[report_id] = {
                        "name": report_name,
                        "integrated_at": datetime.now().isoformat(),
                        "status": "all_iocs_exist",
                        "ioc_count": iocs_already_count
                    }
                    self._save_stix_tracking(stix_tracking)
                    skipped_count += 1
                    continue
                elif iocs_already_count > 0:
                    logger.info(f"[PARTIAL] {iocs_already_count}/{len(indicators_in_report)} IOCs déjà dans MISP pour : {report_name} — import quand même")

                # ── Import du mini-bundle STIX ──
                report_objects = [report]
                
                # Ajouter l'identité si référencée
                if report.get("created_by_ref") in other_objects:
                    report_objects.append(other_objects[report["created_by_ref"]])
                
                # Ajouter tous les objets référencés
                for ref_id in report.get("object_refs", []):
                    if ref_id in other_objects:
                        report_objects.append(other_objects[ref_id])
                
                mini_bundle = {
                    "type": "bundle",
                    "id": f"bundle--{uuid.uuid4()}",
                    "objects": report_objects
                }

                # Sauvegarder temporairement le mini-bundle
                temp_path = stix_file_path + ".tmp.json"
                with open(temp_path, 'w', encoding='utf-8') as f:
                    json.dump(mini_bundle, f)

                try:
                    # Importer le mini-bundle
                    res = self.misp.upload_stix(temp_path, version=2)
                    
                    import time
                    time.sleep(0.2) # Petit délai pour Windows filesystem

                    # Gérer si res est un objet Response ou un dictionnaire
                    if hasattr(res, 'json'):
                        res_data = res.json()
                        status_ok = res.status_code in [200, 201]
                    else:
                        res_data = res
                        status_ok = isinstance(res, dict) and "errors" not in res

                    if status_ok:
                        success_count += 1

                        # Marquer comme intégré dans le tracking
                        stix_tracking.setdefault("integrated_reports", {})[report_id] = {
                            "name": report_name,
                            "integrated_at": datetime.now().isoformat(),
                            "status": "imported",
                            "ioc_count": len(indicators_in_report),
                            "iocs_already_existed": iocs_already_count
                        }
                        
                        try:
                            created_events = res_data if isinstance(res_data, list) else [res_data]
                            if created_events and "Event" in created_events[0]:
                                event_id = created_events[0]["Event"]["id"]
                                event_uuid = created_events[0]["Event"]["uuid"]
                                
                                # Extraire les infos SOC du STIX
                                priority = report.get('x_soc_priority', 'LOW')
                                threat_level_id = self._get_threat_level(priority)
                                
                                # Mettre à jour le titre et le Threat Level
                                self.misp.update_event({
                                    'id': event_id,
                                    'info': report_name,
                                    'threat_level_id': threat_level_id
                                })
                                
                                # Taguer l'événement avec les infos SOC complètes
                                soc_tags = [
                                    f"soc:priority=\"{priority}\"",
                                    f"soc:risk-score=\"{report.get('x_soc_risk', 0)}\"",
                                    f"soc:action=\"{report.get('x_soc_action', 'monitor')}\"",
                                    f"soc:threat-type=\"{report.get('x_soc_threat_type', 'unknown')}\""
                                ]
                                for tag in soc_tags:
                                    try:
                                        self.misp.tag(event_uuid, tag)
                                    except Exception:
                                        pass
                                logger.info(f"[OK] Importé et renommé ({success_count}/{len(reports)}) : {report_name}")
                            else:
                                logger.info(f"[OK] Importé ({success_count}/{len(reports)}) : {report_name}")
                        except Exception as e:
                            logger.warning(f"Import réussi mais erreur lors du renommage : {e}")
                    else:
                        err = res_data.get('errors') if isinstance(res_data, dict) else "Erreur inconnue"
                        logger.error(f"Erreur pour {report_name} : {err}")
                finally:
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except:
                        pass
                    
                    # Sauvegarder le tracking mis à jour à chaque événement
                    self._save_stix_tracking(stix_tracking)

            logger.info(f"══ Résumé : {success_count} importés, {skipped_count} ignorés sur {len(reports)} reports ══")
            return success_count > 0 or skipped_count > 0

        except Exception as e:
            logger.error(f"Exception lors du découpage STIX : {e}")
            return False

    @staticmethod
    def _extract_ioc_from_stix_pattern(pattern):
        """
        Extrait la valeur d'un IOC depuis un pattern STIX 2.1.
        Ex: "[ipv4-addr:value = '1.2.3.4']" → "1.2.3.4"
        """
        import re
        match = re.search(r"=\s*'([^']+)'", pattern)
        if match:
            return match.group(1)
        return None

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
            
            # Tenter d'extraire la date si dispo
            event_date = event_data.get("date")
            event_uuid = self._get_or_create_event_by_info(info_string, event_date=event_date)
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
                        attr_data["integrated_at"] = datetime.now().isoformat()
                        file_modified = True
                    elif isinstance(res, dict) and "errors" in res:
                        err_msg = str(res['errors'])
                        # Si déjà présent ou invalide, on marque quand même comme traité pour ne pas boucler dessus
                        if 'A similar attribute already exists' in err_msg or 'Invalid CIDR' in err_msg:
                            logger.info(f"Sauté (déjà présent ou invalide) : {attr_data['value']}")
                            attr_data["integre_par_misp"] = 1
                            attr_data["integrated_at"] = attr_data.get("integrated_at") or datetime.now().isoformat()
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
        Synchronise les bundles STIX 2.1 vers MISP.
        Cherche tous les fichiers stix_export_*.json et les importe avec tracking.
        Détecte automatiquement les fichiers et reports déjà intégrés.
        """
        corr_dir = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "output_correlation")
        if not os.path.exists(corr_dir):
            logger.error(f"Dossier introuvable : {corr_dir}")
            return

        tracking_data = self._load_tracking()

        # Clean up stray temp files left by previous crashed runs
        for f in os.listdir(corr_dir):
            if f.startswith("stix_export") and ".tmp" in f:
                try:
                    os.remove(os.path.join(corr_dir, f))
                    logger.info(f"[CLEANUP] Fichier temporaire orphelin supprimé : {f}")
                except Exception:
                    pass

        # Chercher les fichiers STIX (stix_export_*.json ou stix_export.json) — exclure les .tmp
        stix_files = [f for f in os.listdir(corr_dir) if f.startswith("stix_export") and f.endswith(".json") and ".tmp" not in f]

        if not stix_files:
            logger.info("Aucun fichier STIX à importer. Assurez-vous d'avoir exécuté stix_exporter.py d'abord.")
            return

        # Trier par date de modification (le plus ancien en premier)
        stix_files.sort(key=lambda f: os.path.getmtime(os.path.join(corr_dir, f)))

        logger.info(f"Fichiers STIX détectés : {len(stix_files)}")

        success_any = False
        for filename in stix_files:
            if filename in tracking_data:
                logger.info(f"[SKIP] Fichier STIX déjà importé (tracking) : {filename}")
                continue

            stix_path = os.path.join(corr_dir, filename)
            file_size = os.path.getsize(stix_path) / (1024 * 1024)
            logger.info(f"Début de l'importation STIX : {filename} ({file_size:.1f} MB)")

            success = self.push_stix_bundle(stix_path)
            if success:
                logger.info(f"Intégration STIX terminée avec succès pour : {filename}")
                tracking_data[filename] = {
                    "imported_at": datetime.now().isoformat(),
                    "file_size_mb": round(file_size, 2)
                }
                self._save_tracking(tracking_data)
                success_any = True
            else:
                logger.error(f"L'intégration STIX a échoué pour : {filename}")

        if not success_any and stix_files:
            logger.info("Aucun nouveau fichier STIX n'avait besoin d'être importé ou erreur survenue.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synchronisation vers MISP")
    parser.add_argument("-f", "--file", help="Fichier JSON spécifique")
    parser.add_argument("-x", "--stix", help="Fichier STIX 2.1 spécifique")
    parser.add_argument("-s", "--source", help="Filtrer par source")
    args = parser.parse_args()

    client = MISPClient()
    if not client.misp:
        exit(1)

    if args.file:
        client.push_event_file(args.file)
    elif args.stix:
        client.push_stix_bundle(args.stix)
    else:
        client.push_all(source_filter=args.source)