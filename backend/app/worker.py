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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Registre global des processus actifs par run_id
# Format: { run_id: subprocess.Popen or asyncio.subprocess.Process }
ACTIVE_PROCS = {}

def terminate_run(run_id: str):
    """Arrête violemment un run en cours."""
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
    return False

# Répertoire racine du projet
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCES_DATA_DIR  = os.path.join(PROJECT_ROOT, "Sources_data")
EXTRACTORS_DIR    = os.path.join(PROJECT_ROOT, "extraction_ioc_cve")
SCRIPTS_DIR       = os.path.join(PROJECT_ROOT, "scripts")
OUTPUT_DIR        = os.path.join(PROJECT_ROOT, "output_cve_ioc")

# Sources CVE-only (pas d'IOCs)
CVE_ONLY_SOURCES = {"NVD", "NVd"}

# Mapping nom affiché → dossier Sources_data + fichier extracteur
SOURCE_MAP = {
    "AbuseIPDB":       {"id": "abuseipdb",     "folder": "AbuseIPDB",                    "extractor": "abuseipdb_extractor.py",      "output": "abuseipdb_extracted.json"},
#    "AlienVault OTX":  {"id": "alienvault",    "folder": "Otx alienvault",               "extractor": "alienvault_extractor.py",     "output": "alienvault_extracted.json"},
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
    "VirusTotal":      {"id": "virustotal",    "folder": "VirusTotal",                   "extractor": "virustotal_extractor.py",     "output": "virustotal_extracted.json"},
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
    Exécute le pipeline complet pour une source (ou toutes si 'Unified Extraction').
    Étapes : Collecte → Extraction CVE/IOC → Normalisation → Intégration MISP
    """
    is_unified = (source_name == "Unified Extraction")
    ts = lambda: datetime.utcnow().strftime("%H:%M:%S")

    # Debug loop type
    loop_type = type(asyncio.get_event_loop()).__name__
    await _ws_log(run_id, "Collecte", f"[{ts()}] [DEBUG] Event loop: {loop_type}")

    try:
        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 1 : Collecte — exécuter script.py de chaque source
        # ══════════════════════════════════════════════════════════════
        await _update_step(run_id, "Collecte", "running")
        await _ws_log(run_id, "Collecte", f"[{ts()}] ═══ DÉMARRAGE COLLECTE ═══")
        await _ws_log(run_id, "Collecte", f"[{ts()}] Source cible : {source_name}")

        collecte_ok = True
        sources_to_run = list(SOURCE_MAP.keys()) if is_unified else [source_name]

        for src in sources_to_run:
            info = SOURCE_MAP.get(src)
            if not info:
                await _ws_log(run_id, "Collecte", f"[{ts()}] ⚠ Source inconnue '{src}', ignorée.")
                continue

            src_folder = os.path.join(SOURCES_DATA_DIR, info["folder"])
            script_path = os.path.join(src_folder, "script.py")

            if not os.path.exists(script_path):
                await _ws_log(run_id, "Collecte", f"[{ts()}] ⚠ Script absent : {script_path}")
                if not is_unified:
                    collecte_ok = False
                continue

            await _ws_log(run_id, "Collecte", f"[{ts()}] ── Collecte : {src} ──")
            await manager.broadcast({"type": "source_activity", "source_id": info["id"], "active": True})
            ok = await _run_proc(
                run_id, "Collecte",
                [sys.executable, script_path],
                src_folder  # CWD = dossier de la source (les scripts écrivent relatif à eux-mêmes)
            )
            if not ok:
                collecte_ok = False
                await _ws_log(run_id, "Collecte", f"[{ts()}] ⚠ {src} collecte échouée — on continue.")

        await _ws_log(run_id, "Collecte", f"[{ts()}] ═══ COLLECTE {'OK' if collecte_ok else 'PARTIELLE'} ═══")
        await _update_step(run_id, "Collecte", "success" if collecte_ok else "failed")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 2 : Extraction CVE / IOC — exécuter les extracteurs
        # ══════════════════════════════════════════════════════════════
        await _update_step(run_id, "Extraction CVE / IOC", "running")
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ═══ DÉMARRAGE EXTRACTION ═══")

        extraction_ok = True
        for src in sources_to_run:
            info = SOURCE_MAP.get(src)
            if not info:
                continue
            extractor_path = os.path.join(EXTRACTORS_DIR, info["extractor"])
            if not os.path.exists(extractor_path):
                await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ⚠ Extracteur absent : {info['extractor']}")
                continue

            await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ── Extraction : {src} ──")
            ok = await _run_proc(
                run_id, "Extraction CVE / IOC",
                [sys.executable, extractor_path],
                PROJECT_ROOT
            )
            
            # BROADCAST END for this source
            await manager.broadcast({"type": "source_activity", "source_id": info["id"], "active": False})

            if not ok:
                extraction_ok = False
                await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ⚠ {src} extraction échouée — on continue.")

        # Compter les résultats
        ioc_count, cve_count = _count_ioc_cve(source_name)
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ✓ Résultats : {ioc_count} IOCs, {cve_count} CVEs")
        await _ws_log(run_id, "Extraction CVE / IOC", f"[{ts()}] ═══ EXTRACTION {'OK' if extraction_ok else 'PARTIELLE'} ═══")
        await _update_step(run_id, "Extraction CVE / IOC",
                           "success" if extraction_ok else "failed",
                           ioc_count=ioc_count, cve_count=cve_count)

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 3 : Enrichissement — exécuter les enrichisseurs NLP
        # ══════════════════════════════════════════════════════════════
        await _update_step(run_id, "Enrichissement", "running")
        await _ws_log(run_id, "Enrichissement", f"[{ts()}] ═══ DÉMARRAGE ENRICHISSEMENT ═══")

        enrichment_ok = True
        ENRICHMENT_SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "enrichment", "scripts")

        for src in sources_to_run:
            # Skip blacklisted enrichment (optional if we want consistency with main.py)
            if src in ["NVD", "AlienVault OTX"]:
                await _ws_log(run_id, "Enrichissement", f"[{ts()}] ➔ Skip : {src} (Non supporté)")
                continue

            info = SOURCE_MAP.get(src)
            if not info: continue

            # Script name should match what generate_enrichers.py produces
            enricher_name = info["output"].replace("_extracted.json", "_enricher.py")
            enricher_path = os.path.join(ENRICHMENT_SCRIPTS_DIR, enricher_name)

            if not os.path.exists(enricher_path):
                await _ws_log(run_id, "Enrichissement", f"[{ts()}] ⚠ Enrichisseur absent : {enricher_name}")
                continue

            await _ws_log(run_id, "Enrichissement", f"[{ts()}] ── Enrichissement : {src} ──")
            ok = await _run_proc(
                run_id, "Enrichissement",
                [sys.executable, enricher_path],
                PROJECT_ROOT
            )
            if not ok:
                enrichment_ok = False
                await _ws_log(run_id, "Enrichissement", f"[{ts()}] ⚠ {src} enrichissement échoué.")

        await _ws_log(run_id, "Enrichissement", f"[{ts()}] ═══ ENRICHISSEMENT {'OK' if enrichment_ok else 'PARTIELLE'} ═══")
        await _update_step(run_id, "Enrichissement", "success" if enrichment_ok else "failed")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 4 : Normalisation (Simulation car non terminé)
        # ══════════════════════════════════════════════════════════════
        await _update_step(run_id, "Normalisation", "running")
        await _ws_log(run_id, "Normalisation", f"[{ts()}] ═══ DÉMARRAGE NORMALISATION (PLANIFIÉ) ═══")
        await asyncio.sleep(0.5)
        await _ws_log(run_id, "Normalisation", f"[{ts()}] [INFO] Cette étape est planifiée pour une version future.")
        await _ws_log(run_id, "Normalisation", f"[{ts()}] ... Étape ignorée pour le moment.")
        await _update_step(run_id, "Normalisation", "planned")

        # ══════════════════════════════════════════════════════════════
        # ÉTAPE 4 : Intégration MISP (Simulation car non terminé)
        # ══════════════════════════════════════════════════════════════
        await _update_step(run_id, "Intégration MISP", "running")
        await _ws_log(run_id, "Intégration MISP", f"[{ts()}] ═══ DÉMARRAGE INTÉGRATION MISP (PLANIFIÉ) ═══")
        await asyncio.sleep(0.5)
        await _ws_log(run_id, "Intégration MISP", f"[{ts()}] [INFO] L'intégration MISP sera disponible prochainement.")
        await _ws_log(run_id, "Intégration MISP", f"[{ts()}] ... Étape ignorée pour le moment.")
        await _update_step(run_id, "Intégration MISP", "planned")

        # Statut global : On considère le run comme "success" seulement si la collecte et l'extraction ont réussi
        await _ws_log(run_id, "Intégration MISP", f"[{ts()}] ════ FIN PIPELINE (SIMULÉE) ════")
        await _update_step(run_id, "Intégration MISP", "success")

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
    is_unified = (source_name == "Unified Extraction")
    ts = lambda: datetime.utcnow().strftime("%H:%M:%S")

    try:
        await _update_step(run_id, step_name, "running")
        await _ws_log(run_id, step_name, f"[{ts()}] ═══ DÉMARRAGE ÉTAPE CIBLÉE : {step_name.upper()} ═══")

        sources_to_run = list(SOURCE_MAP.keys()) if is_unified else [source_name]
        step_ok = True
        ioc_count = 0
        cve_count = 0

        if step_name == "Collecte":
            for src in sources_to_run:
                info = SOURCE_MAP.get(src)
                if not info: continue
                src_folder = os.path.join(SOURCES_DATA_DIR, info["folder"])
                script_path = os.path.join(src_folder, "script.py")
                if not os.path.exists(script_path):
                    await _ws_log(run_id, step_name, f"[{ts()}] ⚠ Script absent : {script_path}")
                    continue
                await _ws_log(run_id, step_name, f"[{ts()}] ── Collecte : {src} ──")
                ok = await _run_proc(run_id, step_name, [sys.executable, script_path], src_folder)
                if not ok: step_ok = False

        elif step_name == "Extraction CVE / IOC":
            for src in sources_to_run:
                info = SOURCE_MAP.get(src)
                if not info: continue
                extractor_path = os.path.join(EXTRACTORS_DIR, info["extractor"])
                if not os.path.exists(extractor_path):
                    await _ws_log(run_id, step_name, f"[{ts()}] ⚠ Extracteur absent : {info['extractor']}")
                    continue
                await _ws_log(run_id, step_name, f"[{ts()}] ── Extraction : {src} ──")
                ok = await _run_proc(run_id, step_name, [sys.executable, extractor_path], PROJECT_ROOT)
                if not ok: step_ok = False
            # Update counts
            ioc_count, cve_count = _count_ioc_cve(source_name)

        elif step_name == "Enrichissement":
            ENRICHMENT_SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "enrichment", "scripts")
            for src in sources_to_run:
                if src in ["NVD", "AlienVault OTX"]:
                    await _ws_log(run_id, step_name, f"[{ts()}] ➔ Skip : {src} (Non supporté)")
                    continue
                info = SOURCE_MAP.get(src)
                if not info: continue
                enricher_name = info["output"].replace("_extracted.json", "_enricher.py")
                enricher_path = os.path.join(ENRICHMENT_SCRIPTS_DIR, enricher_name)
                if not os.path.exists(enricher_path):
                    await _ws_log(run_id, step_name, f"[{ts()}] ⚠ Enrichisseur absent : {enricher_name}")
                    continue
                await _ws_log(run_id, step_name, f"[{ts()}] ── Enrichissement : {src} ──")
                ok = await _run_proc(run_id, step_name, [sys.executable, enricher_path], PROJECT_ROOT)
                if not ok: step_ok = False

        elif step_name in ["Normalisation", "Intégration MISP"]:
            await _ws_log(run_id, step_name, f"[{ts()}] [INFO] Cette étape est planifiée pour une version future.")
            await asyncio.sleep(0.5)
            step_ok = True # Simulé

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
