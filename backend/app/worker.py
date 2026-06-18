import asyncio
import subprocess
import sys
import os
import json
import traceback
import logging
from datetime import datetime
from .database import db
from .websockets import manager

# Configuration du logging pour le worker
logging.basicConfig(encoding="utf-8", level=logging.INFO)
logger = logging.getLogger(__name__)

# Registre global des processus actifs par run_id
# Format: { run_id: subprocess.Popen or asyncio.subprocess.Process }
ACTIVE_PROCS = {}

def terminate_run(run_id: str):
    """Arrête violemment un run en cours."""
    # Mark as failed in DB first so the worker sees it immediately if it checks between steps
    db.update_run(run_id, {"status_global": "failed"})
    
    proc = ACTIVE_PROCS.get(run_id)
    if proc:
        try:
            logger.info(f"Terminating run {run_id} (PID: {proc.pid})...")
            
            if sys.platform == 'win32':
                # Sur Windows, .terminate() ne tue pas les enfants si shell=True.
                # 'taskkill /F /T' tue récursivement toute l'arborescence.
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)], 
                               capture_output=True, text=True)
            else:
                if hasattr(proc, 'terminate'):
                    proc.terminate()
                if hasattr(proc, 'kill'):
                    proc.kill()
                    
            logger.info(f"Run {run_id} terminated via system signal.")
        except Exception as e:
            logger.error(f"Error terminating run {run_id}: {e}")
        finally:
            if run_id in ACTIVE_PROCS:
                del ACTIVE_PROCS[run_id]
        
        return True
    return True # Return true even if no proc found, as long as we marked it failed.

def _is_run_cancelled(run_id: str) -> bool:
    """Vérifie si le run a été marqué comme échoué/arrêté dans la base."""
    run = db.get_run_by_external_id(run_id)
    if not run:
        return True
    return run.get("status_global") == "failed"

# Répertoire racine du projet
PROJECT_ROOT      = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCES_DATA_DIR  = os.path.join(PROJECT_ROOT, "Sources_data")
EXTRACTORS_DIR    = os.path.join(PROJECT_ROOT, "extraction_ioc_cve")
SCRIPTS_DIR       = os.path.join(PROJECT_ROOT, "scripts")
OUTPUT_DIR        = os.path.join(PROJECT_ROOT, "output_cve_ioc")
COLLECTION_SCRIPT = os.path.join(SCRIPTS_DIR, "run_collection_all.py")
LEAK_INTEGRATION_SCRIPT = os.path.join(PROJECT_ROOT, "leak_data_integration", "main.py")
ENRICHMENT_DIR    = os.path.join(PROJECT_ROOT, "enrichment")
CORRELATION_SCRIPT = os.path.join(PROJECT_ROOT, "misp_integration", "correlation_pre_misp.py")
STIX_EXPORT_SCRIPT = os.path.join(PROJECT_ROOT, "misp_integration", "stix_exporter.py")

# Sources CVE-only (pas d'IOCs)
CVE_ONLY_SOURCES = {"NVD", "NVd"}

# Mapping nom affiché → dossier Sources_data + fichier extracteur
SOURCE_MAP = {
    "AlienVault OTX":  {"id": "alienvault",    "folder": "Otx alienvault",               "extractor": "alienvault_extractor.py",     "output": "alienvault_extracted.json"},
    "CINS Army":       {"id": "cins_army",     "folder": "CINS Army",                    "extractor": "cins_army_extractor.py",      "output": "cins_army_extracted.json"},
    "FeodoTracker":    {"id": "feodotracker",  "folder": "feodotracker",                  "extractor": "feodotracker_extractor.py",   "output": "feodotracker_extracted.json"},
    "MalwareBazaar":   {"id": "malwarebazaar", "folder": "MalwareBazaar Community API",  "extractor": "malwarebazaar_extractor.py",  "output": "malwarebazaar_extracted.json"},
    "NVD":             {"id": "nvd",           "folder": "NVd",                           "extractor": "nvd_extractor.py",            "output": "nvd_extracted.json"},
    "OpenPhish":       {"id": "openphish",     "folder": "OpenPhish",                    "extractor": "openphish_extractor.py",      "output": "openphish_extracted.json"},
    "PhishTank":       {"id": "phishtank",     "folder": "PhishTank",                    "extractor": "phishtank_extractor.py",      "output": "phishtank_extracted.json"},
    "PulseDive":       {"id": "pulsedive",     "folder": "pulsedive",                    "extractor": "pulsedive_extractor.py",      "output": "pulsedive_extracted.json"},
    "Spamhaus":        {"id": "spamhaus",      "folder": "Spamhaus",                     "extractor": "spamhaus_extractor.py",       "output": "spamhaus_extracted.json"},
    "ThreatFox":       {"id": "threatfox",     "folder": "ThreatFox",                    "extractor": "threatfox_extractor.py",      "output": "threatfox_extracted.json"},
    "URLhaus":         {"id": "urlhaus",       "folder": "url",                          "extractor": "urlhaus_extractor.py",        "output": "urlhaus_extracted.json"},
    "DFIR Report":     {"id": "dfir_report",   "folder": "The DFIR Report",              "extractor": "dfir_report_extractor.py",    "output": "dfir_report_extracted.json"},
}


# ─── Helpers WebSocket ──────────────────────────────────────────────────────────

async def _ws_log(run_id: str, step_name: str, line: str):
    """Envoie une ligne de log via WebSocket et la sauvegarde en DB."""
    db.append_log(run_id, step_name, line)
    await manager.broadcast({
        "type": "log",
        "run_id": run_id,
        "step_name": step_name,
        "line": line,
    })


async def _run_proc(run_id: str, step_name: str, cmd: list, cwd: str) -> bool:
    """
    Lance un sous-processus. 
    Sur Windows, si asyncio échoue avec NotImplementedError, utilise un fallback synchrone dans un thread.
    """
    ts_func = lambda: datetime.utcnow().strftime("%H:%M:%S")
    cmd_str = ' '.join(f'"{str(c)}"' if ' ' in str(c) else str(c) for c in cmd)
    await _ws_log(run_id, step_name, f"[{ts_func()}] $ {cmd_str}")
    
    try:
        # Tentative normale via asyncio
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            
            # Enregistrement pour pouvoir l'arrêter
            ACTIVE_PROCS[run_id] = proc
            
            async for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    await _ws_log(run_id, step_name, f"[{ts_func()}] {line}")
            
            await proc.wait()
            
            # Check if it was cancelled
            if _is_run_cancelled(run_id):
                await _ws_log(run_id, step_name, f"[{ts_func()}] \u26a0 Processus arrêté par l'utilisateur.")
                return False

            ok = proc.returncode == 0
            
            # Nettoyage
            if run_id in ACTIVE_PROCS: del ACTIVE_PROCS[run_id]
            
            status_icon = "\u2713" if ok else "\u2717"
            await _ws_log(run_id, step_name, f"[{ts_func()}] {status_icon} Processus terminé (code {proc.returncode})")
            return ok

        except NotImplementedError:
            # FALLBACK CRITIQUE POUR WINDOWS :
            # Si la loop asyncio ne supporte pas les subprocesses, on utilise subprocess.Popen dans un thread.
            await _ws_log(run_id, step_name, f"[{ts_func()}] \u26a0 Loop asyncio Selector détectée. Utilisation du fallback synchrone...")
            
            def run_sync():
                p = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    encoding="utf-8",
                    errors="replace",
                    shell=(sys.platform == 'win32')
                )
                return p

            # On capture la boucle actuelle avant de passer dans le thread
            main_loop = asyncio.get_running_loop()
            
            # On lance dans un thread pour ne pas bloquer l'event loop
            proc_sync = await asyncio.to_thread(run_sync)
            
            # Enregistrement
            ACTIVE_PROCS[run_id] = proc_sync
            
            # Lecture des logs en streaming
            def stream_logs(p, rid, sname, loop):
                for line in p.stdout:
                    line = line.strip()
                    if line:
                        asyncio.run_coroutine_threadsafe(
                            _ws_log(rid, sname, f"[{ts_func()}] {line}"),
                            loop
                        )
                p.wait()
                return p.returncode

            return_code = await asyncio.to_thread(stream_logs, proc_sync, run_id, step_name, main_loop)
            
            # Check if it was cancelled
            if _is_run_cancelled(run_id):
                await _ws_log(run_id, step_name, f"[{ts_func()}] \u26a0 Processus arrêté par l'utilisateur (fallback).")
                return False

            # Nettoyage
            if run_id in ACTIVE_PROCS: del ACTIVE_PROCS[run_id]
            
            ok = return_code == 0
            status_icon = "\u2713" if ok else "\u2717"
            await _ws_log(run_id, step_name, f"[{ts_func()}] {status_icon} Processus terminé via fallback (code {return_code})")
            return ok

    except Exception as e:
        if run_id in ACTIVE_PROCS: del ACTIVE_PROCS[run_id]
        error_detail = traceback.format_exc()
        await _ws_log(run_id, step_name, f"[{ts_func()}] \u2717 ERREUR CRITIQUE DANS LE WORKER:")
        for line in error_detail.split('\n'):
            if line.strip():
                await _ws_log(run_id, step_name, f"[{ts_func()}]   > {line}")
        return False


async def _update_step(run_id: str, step_name: str, status: str,
                       ioc_count: int = 0, cve_count: int = 0, error: str = ""):
    step_data = {
        "step_name": step_name,
        "status": status,
        "ioc_count": ioc_count,
        "cve_count": cve_count,
        "error_message": error,
    }
    if status == "running":
        step_data["started_at"] = datetime.utcnow().isoformat()
    elif status in ["success", "failed"]:
        step_data["finished_at"] = datetime.utcnow().isoformat()

    db.update_step(run_id, step_data)
    await manager.broadcast({
        "type": "step_update",
        "run_id": run_id,
        "step_name": step_name,
        "status": status,
        "ioc_count": ioc_count,
        "cve_count": cve_count,
    })


# ─── Comptage IOC/CVE ───────────────────────────────────────────────────────────

def _count_file(filepath: str):
    """Compte IOCs et CVEs dans un fichier JSON de sortie (liste de records)."""
    ioc_count = cve_count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    ioc_count += len(rec.get("iocs", []) or [])
                    cve_count += len(rec.get("cves", []) or [])
        elif isinstance(data, dict):
            ioc_count = len(data.get("iocs", []) or [])
            cve_count = len(data.get("cves", []) or [])
    except Exception:
        pass
    return ioc_count, cve_count


def _count_ioc_cve(source_name: str):
    """
    Lit le fichier output de la source et retourne (ioc_count, cve_count).
    Pour les sources CVE-only (NVD), ioc_count = 0.
    """
    info = SOURCE_MAP.get(source_name)
    is_cve_only = source_name in CVE_ONLY_SOURCES

    if info:
        filepath = os.path.join(OUTPUT_DIR, info["output"])
        if os.path.exists(filepath):
            raw_ioc, raw_cve = _count_file(filepath)
            return (0 if is_cve_only else raw_ioc), raw_cve
        return 0, 0
    else:
        # Pipeline unifié : somme de tous les fichiers
        total_ioc = total_cve = 0
        if os.path.exists(OUTPUT_DIR):
            for src_name, src_info in SOURCE_MAP.items():
                fp = os.path.join(OUTPUT_DIR, src_info["output"])
                if os.path.exists(fp):
                    raw_ioc, raw_cve = _count_file(fp)
                    total_ioc += 0 if src_name in CVE_ONLY_SOURCES else raw_ioc
                    total_cve += raw_cve
        return total_ioc, total_cve


# ─── Pipeline principal ─────────────────────────────────────────────────────────

async def execute_pipeline_task(run_id: str, source_name: str):
    """
    Exécute le pipeline complet pour une source (ou toutes si 'Pipeline Complet').
    Étapes : Collecte → Extraction CVE/IOC → Normalisation → Intégration MISP
    """
    is_unified = (source_name == "Pipeline Complet")
    ts = lambda: datetime.utcnow().strftime("%H:%M:%S")

    # Debug loop type
    loop_type = type(asyncio.get_event_loop()).__name__
    await _ws_log(run_id, "Collecte", f"[{ts()}] [DEBUG] Event loop: {loop_type}")

    try:
        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 1 : Collecte — exécuter script.py de chaque source
        # ══════════════════════════════════════════════════════════════
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Collecte", "running")
        await _ws_log(run_id, "Collecte", f"[{ts()}] ═══ DÉMARRAGE COLLECTE ═══")
        await _ws_log(run_id, "Collecte", f"[{ts()}] Source cible : {source_name}")

        collecte_ok = True
        sources_to_run = list(SOURCE_MAP.keys()) if is_unified else [source_name]

        if is_unified:
            await _ws_log(run_id, "Collecte", f"[{ts()}] ➔ Utilisation de l'orchestrateur global : run_collection_all.py")
            collecte_ok = await _run_proc(run_id, "Collecte", [sys.executable, COLLECTION_SCRIPT], PROJECT_ROOT)
        else:
            for src in sources_to_run:
                if _is_run_cancelled(run_id): break
                if src == "AlienVault OTX":
                    await _ws_log(run_id, "Collecte", f"[{ts()}] ℹ {src} ignoré pour la collecte (Configuration).")
                    continue

                info = SOURCE_MAP.get(src)

                src_folder = os.path.join(SOURCES_DATA_DIR, info["folder"])
                script_path = os.path.join(src_folder, "script.py")

                if not os.path.exists(script_path):
                    await _ws_log(run_id, "Collecte", f"[{ts()}] ⚠ Script absent : {script_path}")
                    collecte_ok = False
                    continue

                await _ws_log(run_id, "Collecte", f"[{ts()}] ── Collecte : {src} ──")
                await manager.broadcast({"type": "source_activity", "source_id": info["id"], "active": True})
                ok = await _run_proc(
                    run_id, "Collecte",
                    [sys.executable, script_path],
                    src_folder
                )
                if not ok:
                    collecte_ok = False
                    await _ws_log(run_id, "Collecte", f"[{ts()}] ⚠ {src} collecte échouée — on continue.")

        await _ws_log(run_id, "Collecte", f"[{ts()}] ═══ COLLECTE {'OK' if collecte_ok else 'PARTIELLE'} ═══")
        await _update_step(run_id, "Collecte", "success" if collecte_ok else "failed")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 2 : Extraction CVE / IOC — exécuter les extracteurs
        # ══════════════════════════════════════════════════════════════
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Extraction CVE / IOC", "running")
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ═══ DÉMARRAGE EXTRACTION ═══")

        if is_unified:
            await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ➔ Utilisation de l'orchestrateur global : run_extraction_all.py")
            extraction_script = os.path.join(EXTRACTORS_DIR, "run_extraction_all.py")
            extraction_ok = await _run_proc(run_id, "Extraction CVE / IOC", [sys.executable, extraction_script], PROJECT_ROOT)
        else:
            extraction_ok = True
            for src in sources_to_run:
                if _is_run_cancelled(run_id): break
                info = SOURCE_MAP.get(src)
                if not info: continue
                extractor_path = os.path.join(EXTRACTORS_DIR, info["extractor"])
                if not os.path.exists(extractor_path):
                    await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ⚠ Extracteur absent : {info['extractor']}")
                    continue
                await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ── Extraction : {src} ──")
                ok = await _run_proc(run_id, "Extraction CVE / IOC", [sys.executable, extractor_path], PROJECT_ROOT)
                await manager.broadcast({"type": "source_activity", "source_id": info["id"], "active": False})
                if not ok: extraction_ok = False

        # Compter les résultats
        ioc_count, cve_count = _count_ioc_cve(source_name)
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ✓ Résultats : {ioc_count} IOCs, {cve_count} CVEs")
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ═══ EXTRACTION {'OK' if extraction_ok else 'PARTIELLE'} ═══")
        await _update_step(run_id, "Extraction CVE / IOC",
                           "success" if extraction_ok else "failed",
                           ioc_count=ioc_count, cve_count=cve_count)

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 3à5 : Enrichissement Granulaire (NLP -> Geo -> Scan)
        # ══════════════════════════════════════════════════════════════
        source_flag = ["-s", source_name] if not is_unified else []

        # Initialisation des fichiers d'enrichissement (copie/split)
        await _ws_log(run_id, "Geolocalisation", f"[{ts()}] ➔ Initialisation des fichiers d'enrichissement...")
        init_script = os.path.join(PROJECT_ROOT, "enrichment", "initialize_enrichment.py")
        await _run_proc(run_id, "Geolocalisation", [sys.executable, init_script] + source_flag, PROJECT_ROOT)

        # Geolocation
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Geolocalisation", "running")
        await _ws_log(run_id, "Geolocalisation", f"[{ts()}] ➔ STAGE 2 : Géolocalisation")
        geo_script = os.path.join(PROJECT_ROOT, "enrichment", "geolocalisation", "enrichir.py")
        geo_ok = await _run_proc(run_id, "Geolocalisation", [sys.executable, geo_script] + source_flag, PROJECT_ROOT)
        await _update_step(run_id, "Geolocalisation", "success" if geo_ok else "failed")

        # URLScan & Fallback (Stage 3 & 4)
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "URLScan", "running")
        await _ws_log(run_id, "URLScan", f"[{ts()}] ➔ STAGE 3 & 4 : URL Analysis & Fallback")
        url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_exclusive_urlscan.py")
        fallback_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_fallback.py")
        
        ok3 = await _run_proc(run_id, "URLScan", [sys.executable, url_script] + source_flag, PROJECT_ROOT)
        ok4 = await _run_proc(run_id, "URLScan", [sys.executable, fallback_script] + source_flag, PROJECT_ROOT)
        
        await _update_step(run_id, "URLScan", "success" if (ok3 and ok4) else "failed")

        # CVE Enrichment (Consolidated: NVD + NLP)
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Enrichissement CVE", "running")
        await _ws_log(run_id, "Enrichissement CVE", f"[{ts()}] ➔ STAGE 5 : Consolidated CVE Enrichment (NVD & NLP)")
        cve_orchestrator = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_cve", "cve_enrchisment.py")
        ok_cve = await _run_proc(run_id, "Enrichissement CVE", [sys.executable, cve_orchestrator] + source_flag, PROJECT_ROOT)
        await _update_step(run_id, "Enrichissement CVE", "success" if ok_cve else "failed")

        # AbuseIPDB Enrichment
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "AbuseIPDB Enrichment", "running")
        await _ws_log(run_id, "AbuseIPDB Enrichment", f"[{ts()}] ➔ STAGE 1 : AbuseIPDB Reputation Enrichment")
        abuseipdb_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_ip", "enrichir_abuseipdb.py")
        ok_abuse = await _run_proc(run_id, "AbuseIPDB Enrichment", [sys.executable, abuseipdb_script] + source_flag, PROJECT_ROOT)
        await _update_step(run_id, "AbuseIPDB Enrichment", "success" if ok_abuse else "failed")

        # VirusTotal Enrichment
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "VirusTotal Enrichment", "running")
        await _ws_log(run_id, "VirusTotal Enrichment", f"[{ts()}] ➔ STAGE 1b : VirusTotal Enrichment")
        virustotal_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_vt", "enrichir_virustotal.py")
        ok_vt = await _run_proc(run_id, "VirusTotal Enrichment", [sys.executable, virustotal_script] + source_flag, PROJECT_ROOT)
        await _update_step(run_id, "VirusTotal Enrichment", "success" if ok_vt else "failed")

        # Intelligence Classification (Stage 7)
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Classification", "running")
        await _ws_log(run_id, "Classification", f"[{ts()}] ➔ STAGE 7 : Intelligence Classification & Priority")
        classif_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "enrichir.py")
        ok7 = await _run_proc(run_id, "Classification", [sys.executable, classif_script] + source_flag + ["--skip-enriched"], PROJECT_ROOT)
        await _update_step(run_id, "Classification", "success" if ok7 else "failed")

        # MITRE ATT&CK Mapping (Stage 8)
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "MITRE Mapping", "running")
        await _ws_log(run_id, "MITRE Mapping", f"[{ts()}] ➔ STAGE 8 : MITRE ATT&CK Mapping")
        mitre_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "mitre_mapper.py")
        ok8 = await _run_proc(run_id, "MITRE Mapping", [sys.executable, mitre_script] + source_flag + ["--skip-mapped"], PROJECT_ROOT)
        await _update_step(run_id, "MITRE Mapping", "success" if ok8 else "failed")



        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 6 : Corrélation SOC (Remplaçant Normalisation)
        # ══════════════════════════════════════════════════════════════
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Corrélation SOC", "running")
        await _ws_log(run_id, "Corrélation SOC", f"[{ts()}] ➔ STAGE 9 : Corrélation & Groupement des menaces")
        ok_corr = await _run_proc(run_id, "Corrélation SOC", [sys.executable, CORRELATION_SCRIPT], PROJECT_ROOT)
        await _update_step(run_id, "Corrélation SOC", "success" if ok_corr else "failed")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 7 : Export STIX 2.1
        # ══════════════════════════════════════════════════════════════
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Export STIX", "running")
        await _ws_log(run_id, "Export STIX", f"[{ts()}] ➔ STAGE 10 : Génération du bundle STIX 2.1")
        ok_stix = await _run_proc(run_id, "Export STIX", [sys.executable, STIX_EXPORT_SCRIPT], PROJECT_ROOT)
        await _update_step(run_id, "Export STIX", "success" if ok_stix else "failed")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 8 : Intégration MISP
        # ══════════════════════════════════════════════════════════════
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, "Intégration MISP", "running")
        await _ws_log(run_id, "Intégration MISP", f"[{ts()}] ➔ STAGE 11 : Intégration MISP (API Push)")
        misp_api_script = os.path.join(PROJECT_ROOT, "misp_integration", "misp_api_integration.py")
        ok_misp = await _run_proc(run_id, "Intégration MISP", [sys.executable, misp_api_script], PROJECT_ROOT)
        await _update_step(run_id, "Intégration MISP", "success" if ok_misp else "failed")


        # Terminer
        db.update_run(run_id, {"status_global": "success"})
        await manager.broadcast({"type": "run_complete", "run_id": run_id, "status": "success"})

    except Exception as e:
        logger.error(f"Pipeline error: {e}", exc_info=True)
        await _ws_log(run_id, "Collecte", f"[{ts()}] ❌ ERREUR FATALE : {e}")
        db.update_run(run_id, {"status_global": "failed"})
        await manager.broadcast({"type": "run_complete", "run_id": run_id, "status": "failed"})

async def execute_enrichment_task(run_id: str, source_name: str):
    """Wrapper pour l'enrichissement uniquement."""
    await execute_targeted_task(run_id, source_name, "Enrichissement")

async def execute_targeted_task(run_id: str, source_name: str, step_name: str):
    """
    Exécute UNIQUEMENT une étape spécifique du pipeline.
    """
    is_unified = (source_name == "Pipeline Complet")
    ts = lambda: datetime.utcnow().strftime("%H:%M:%S")

    try:
        if _is_run_cancelled(run_id): return
        await _update_step(run_id, step_name, "running")
        await _ws_log(run_id, step_name, f"[{ts()}] ═══ DÉMARRAGE ÉTAPE CIBLÉE : {step_name.upper()} ═══")

        sources_to_run = list(SOURCE_MAP.keys()) if is_unified else [source_name]
        step_ok = True
        ioc_count = 0
        cve_count = 0
        source_flag = ["-s", source_name] if source_name and source_name != "Pipeline Complet" else []

        # Auto-initialize enrichment files if executing an enrichment step
        enrichment_steps = {
            "Enrichissement", "AbuseIPDB Enrichment", "VirusTotal Enrichment",
            "Enrichissement CVE", "Analyse NLP CVE", "Geolocalisation",
            "URLScan", "Fallback", "URLScan_Only"
        }
        if step_name in enrichment_steps:
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ Initialisation des fichiers d'enrichissement...")
            init_script = os.path.join(PROJECT_ROOT, "enrichment", "initialize_enrichment.py")
            await _run_proc(run_id, step_name, [sys.executable, init_script] + source_flag, PROJECT_ROOT)

        if step_name == "Collecte":
            if is_unified:
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ Orchestrateur Global : run_collection_all.py")
                step_ok = await _run_proc(run_id, step_name, [sys.executable, COLLECTION_SCRIPT], PROJECT_ROOT)
            else:
                for src in sources_to_run:
                    if _is_run_cancelled(run_id): break
                    if src == "AlienVault OTX":
                        await _ws_log(run_id, step_name, f"[{ts()}] ℹ {src} ignoré pour la collecte (Configuration).")
                        continue
                    info = SOURCE_MAP.get(src)
                    if not info: continue
                    src_folder = os.path.join(SOURCES_DATA_DIR, info["folder"])
                    script_path = os.path.join(src_folder, "script.py")
                    if not os.path.exists(script_path): continue
                    await _ws_log(run_id, step_name, f"[{ts()}] ── Collecte : {src} ──")
                    ok = await _run_proc(run_id, step_name, [sys.executable, script_path], src_folder)
                    if not ok: step_ok = False

        elif step_name == "Extraction CVE / IOC":
            if is_unified:
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ Orchestrateur Global : run_extraction_all.py")
                extraction_script = os.path.join(EXTRACTORS_DIR, "run_extraction_all.py")
                step_ok = await _run_proc(run_id, step_name, [sys.executable, extraction_script], PROJECT_ROOT)
            else:
                for src in sources_to_run:
                    if _is_run_cancelled(run_id): break
                    info = SOURCE_MAP.get(src)
                    if not info: continue
                    extractor_path = os.path.join(EXTRACTORS_DIR, info["extractor"])
                    if not os.path.exists(extractor_path): continue
                    await _ws_log(run_id, step_name, f"[{ts()}] ── Extraction : {src} ──")
                    ok = await _run_proc(run_id, step_name, [sys.executable, extractor_path], PROJECT_ROOT)
                    if not ok: step_ok = False
            # Update counts
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Enrichissement":
            if is_unified:
                # Run each sub-step individually so each gets its own DB status (phase dots turn green)
                await _ws_log(run_id, "Enrichissement", f"[{ts()}] ═══ DÉMARRAGE ENRICHISSEMENT UNIFIÉ ═══")

                # Init
                await _ws_log(run_id, "Enrichissement", f"[{ts()}] ➔ Initialisation des fichiers...")
                init_script = os.path.join(PROJECT_ROOT, "enrichment", "initialize_enrichment.py")
                await _run_proc(run_id, "Enrichissement", [sys.executable, init_script], PROJECT_ROOT)

                # AbuseIPDB
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "AbuseIPDB Enrichment", "running")
                    abuseipdb_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_ip", "enrichir_abuseipdb.py")
                    ok_abuse = await _run_proc(run_id, "AbuseIPDB Enrichment", [sys.executable, abuseipdb_script], PROJECT_ROOT)
                    await _update_step(run_id, "AbuseIPDB Enrichment", "success" if ok_abuse else "failed")

                # VirusTotal
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "VirusTotal Enrichment", "running")
                    vt_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_vt", "enrichir_virustotal.py")
                    ok_vt = await _run_proc(run_id, "VirusTotal Enrichment", [sys.executable, vt_script], PROJECT_ROOT)
                    await _update_step(run_id, "VirusTotal Enrichment", "success" if ok_vt else "failed")

                # Geolocalisation
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "Geolocalisation", "running")
                    geo_script = os.path.join(PROJECT_ROOT, "enrichment", "geolocalisation", "enrichir.py")
                    ok_geo = await _run_proc(run_id, "Geolocalisation", [sys.executable, geo_script], PROJECT_ROOT)
                    await _update_step(run_id, "Geolocalisation", "success" if ok_geo else "failed")

                # URLScan + Fallback
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "URLScan", "running")
                    url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_exclusive_urlscan.py")
                    fallback_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_fallback.py")
                    ok_url = await _run_proc(run_id, "URLScan", [sys.executable, url_script], PROJECT_ROOT)
                    ok_fall = await _run_proc(run_id, "URLScan", [sys.executable, fallback_script], PROJECT_ROOT)
                    await _update_step(run_id, "URLScan", "success" if (ok_url and ok_fall) else "failed")

                # CVE Enrichment
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "Enrichissement CVE", "running")
                    cve_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_cve", "cve_enrchisment.py")
                    ok_cve = await _run_proc(run_id, "Enrichissement CVE", [sys.executable, cve_script], PROJECT_ROOT)
                    await _update_step(run_id, "Enrichissement CVE", "success" if ok_cve else "failed")

                # Classification
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "Classification", "running")
                    classif_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "enrichir.py")
                    ok_classif = await _run_proc(run_id, "Classification", [sys.executable, classif_script, "--skip-enriched"], PROJECT_ROOT)
                    await _update_step(run_id, "Classification", "success" if ok_classif else "failed")

                # MITRE Mapping
                if not _is_run_cancelled(run_id):
                    await _update_step(run_id, "MITRE Mapping", "running")
                    mitre_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "mitre_mapper.py")
                    ok_mitre = await _run_proc(run_id, "MITRE Mapping", [sys.executable, mitre_script, "--skip-mapped"], PROJECT_ROOT)
                    await _update_step(run_id, "MITRE Mapping", "success" if ok_mitre else "failed")

                step_ok = not _is_run_cancelled(run_id)
            else:
                # Single source full enrichment
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ Full Enrichment for {source_name}")
                source_flag = ["-s", source_name]

                # AbuseIPDB
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 1 : AbuseIPDB Reputation")
                abuseipdb_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_ip", "enrichir_abuseipdb.py")
                ok_abuse = await _run_proc(run_id, step_name, [sys.executable, abuseipdb_script] + source_flag, PROJECT_ROOT)

                # VirusTotal
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 1b : VirusTotal")
                virustotal_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_vt", "enrichir_virustotal.py")
                ok_vt = await _run_proc(run_id, step_name, [sys.executable, virustotal_script] + source_flag, PROJECT_ROOT)

                # Geo
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 2 : Géolocalisation")
                geo_script = os.path.join(PROJECT_ROOT, "enrichment", "geolocalisation", "enrichir.py")
                ok2 = await _run_proc(run_id, step_name, [sys.executable, geo_script] + source_flag, PROJECT_ROOT)

                # URLScan & Fallback
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 3 & 4 : URLScan & Fallback")
                url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_exclusive_urlscan.py")
                fallback_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichir_fallback.py")

                ok3 = await _run_proc(run_id, step_name, [sys.executable, url_script] + source_flag, PROJECT_ROOT)
                ok4 = await _run_proc(run_id, step_name, [sys.executable, fallback_script] + source_flag, PROJECT_ROOT)

                # CVE Enrichment (Consolidated)
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 5 : Consolidated CVE Enrichment")
                cve_orchestrator = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_cve", "cve_enrchisment.py")
                ok_cve = await _run_proc(run_id, step_name, [sys.executable, cve_orchestrator] + source_flag, PROJECT_ROOT)

                # Classification
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 7 : Intelligence Classification")
                classif_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "enrichir.py")
                ok7 = await _run_proc(run_id, step_name, [sys.executable, classif_script] + source_flag + ["--skip-enriched"], PROJECT_ROOT)

                # MITRE Mapping
                await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 8 : MITRE ATT&CK Mapping")
                mitre_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "mitre_mapper.py")
                ok8 = await _run_proc(run_id, step_name, [sys.executable, mitre_script] + source_flag + ["--skip-mapped"], PROJECT_ROOT)

                step_ok = ok_abuse and ok_vt and ok2 and ok3 and ok4 and ok_cve and ok7 and ok8

        elif step_name == "AbuseIPDB Enrichment":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ AbuseIPDB Enrichment Pipeline")
            abuseipdb_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_ip", "enrichir_abuseipdb.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, abuseipdb_script] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "VirusTotal Enrichment":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ VirusTotal Enrichment Pipeline")
            virustotal_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_vt", "enrichir_virustotal.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, virustotal_script] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Enrichissement CVE":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ CVE Enrichment Pipeline (NVD + NLP)")
            cve_orchestrator = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_cve", "cve_enrchisment.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, cve_orchestrator] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Analyse NLP CVE":
            # Redirection vers l'orchestrateur consolidé si l'utilisateur clique sur NLP
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ Redirection vers le pipeline CVE consolidé...")
            cve_orchestrator = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_cve", "cve_enrchisment.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, cve_orchestrator] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)




        elif step_name == "Geolocalisation":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 2 : Géolocalisation (Infrastructure)")
            geo_script = os.path.join(PROJECT_ROOT, "enrichment", "geolocalisation", "enrichir.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, geo_script] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "URLScan":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ Analyse Complète URL (URLScan + Fallback)")
            master_url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichissement_url.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, master_url_script, "--mode", "both"] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Fallback":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 4 : Recherche Complémentaire / Fallback")
            master_url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichissement_url.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, master_url_script, "--mode", "fallback"] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "URLScan_Only":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 3 : Analyse URLScan.io Uniquement")
            master_url_script = os.path.join(PROJECT_ROOT, "enrichment", "enrichment_url", "enrichissement_url.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, master_url_script, "--mode", "urlscan"] + source_flag, PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Corrélation SOC":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 9 : Corrélation avancée & Groupement")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, CORRELATION_SCRIPT], PROJECT_ROOT)

        elif step_name == "Export STIX":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 10 : Exportation STIX 2.1 (Bundle complet)")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, STIX_EXPORT_SCRIPT], PROJECT_ROOT)

        elif step_name == "Classification":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ Intelligence Classification & Scoring")
            classif_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "enrichir.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, classif_script] + source_flag + ["--skip-enriched"], PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "MITRE Mapping":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ MITRE ATT&CK Technique Mapping")
            mitre_script = os.path.join(PROJECT_ROOT, "enrichment", "classification", "mitre_mapper.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, mitre_script] + source_flag + ["--skip-mapped"], PROJECT_ROOT)
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Normalisation":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ [OBSOLETE] Normalisation des données")
            norm_script = os.path.join(PROJECT_ROOT, "normalisation", "pipeline_runner.py")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, norm_script] + source_flag, PROJECT_ROOT)

        elif step_name == "Intégration MISP":
            await _ws_log(run_id, step_name, f"[{ts()}] ➔ STAGE 5 : Intégration MISP (API Push)")
            misp_api_script = os.path.join(PROJECT_ROOT, "misp_integration", "misp_api_integration.py")
            
            await _ws_log(run_id, step_name, f"[{ts()}] ── Phase 1 : Exportation via API vers MISP ──")
            step_ok = await _run_proc(run_id, step_name, [sys.executable, misp_api_script] + source_flag, PROJECT_ROOT)


        await _ws_log(run_id, step_name, f"[{ts()}] ═══ ÉTAPE {step_name.upper()} {'OK' if step_ok else 'TERMINÉE'} ═══")
        await _update_step(run_id, step_name, "success" if step_ok else "failed", ioc_count=ioc_count, cve_count=cve_count)
        
        # Terminer le run global
        db.update_run(run_id, {"status_global": "success" if step_ok else "failed"})
        await manager.broadcast({"type": "run_complete", "run_id": run_id, "status": "success" if step_ok else "failed"})

    except Exception as e:
        print(f"Error in targeted task: {e}")
        traceback.print_exc()
        await _ws_log(run_id, step_name, f"[{ts()}] ❌ ERREUR FATALE : {e}")
        await _update_step(run_id, step_name, "failed")
        db.update_run(run_id, {"status_global": "failed"})
        await manager.broadcast({"type": "run_complete", "run_id": run_id, "status": "failed"})

async def execute_leak_collection_task(run_id: str, channels: list = None, start_date: str = None):
    """
    Lance le collecteur de fuites Telegram.
    """
    ts = lambda: datetime.utcnow().strftime("%H:%M:%S")
    step_name = "Monitoring Telegram"
    
    try:
        await _update_step(run_id, step_name, "running")
        await _ws_log(run_id, step_name, f"[{ts()}] ═══ DÉMARRAGE MONITORING TELEGRAM ═══")
        
        cmd = [sys.executable, LEAK_INTEGRATION_SCRIPT]
        if channels:
            cmd.extend(["--channels", ",".join(channels)])
        if start_date:
            cmd.extend(["--start-date", start_date])
            
        ok = await _run_proc(run_id, step_name, cmd, os.path.dirname(LEAK_INTEGRATION_SCRIPT))
        
        await _update_step(run_id, step_name, "success" if ok else "failed")
        db.update_run(run_id, {"status_global": "success" if ok else "failed"})
        await manager.broadcast({"type": "run_complete", "run_id": run_id, "status": "success" if ok else "failed"})
        
    except Exception as e:
        logger.error(f"Leak collection error: {e}")
        await _ws_log(run_id, step_name, f"[{ts()}] ❌ ERREUR : {e}")
        db.update_run(run_id, {"status_global": "failed"})
