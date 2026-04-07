import os
import subprocess
import sys
import time

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_DIR = os.path.join(os.path.dirname(BASE_DIR), "Sources_data")
MONITOR_SCRIPT = os.path.join(BASE_DIR, "monitor.py")

def run_script(source_name, script_path):
    """Exécute un script d'extraction individuel."""
    print(f"\n>>> Lancement de l'extraction : {source_name}")
    start_time = time.time()
    
    # On se place dans le dossier du script pour qu'il trouve ses fichiers relatifs (.env, data, etc.)
    script_dir = os.path.dirname(script_path)
    
    try:
        # Exécution du script
        process = subprocess.run(
            [sys.executable, "script.py"],
            cwd=script_dir,
            capture_output=False, # On laisse l'output s'afficher dans la console
            text=True
        )
        
        duration = time.time() - start_time
        if process.returncode == 0:
            print(f"--- SUCCESS : {source_name} terminé en {duration:.2f}s")
            return True
        else:
            print(f"--- FAILED : {source_name} a échoué (code {process.returncode})")
            return False
            
    except Exception as e:
        print(f"--- ERROR : Erreur technique pour {source_name} : {e}")
        return False

def main():
    if not os.path.exists(SOURCES_DIR):
        print(f"Erreur : Dossier {SOURCES_DIR} introuvable.")
        return

    # Découverte des sources
    sources = []
    for source_name in os.listdir(SOURCES_DIR):
        source_path = os.path.join(SOURCES_DIR, source_name)
        script_path = os.path.join(source_path, "script.py")
        
        if os.path.isdir(source_path) and os.path.exists(script_path):
            sources.append((source_name, script_path))

    print("=" * 60)
    print(f"DÉMARRAGE DU RUNNER : {len(sources)} sources détectées")
    print("=" * 60)

    results = {"success": [], "failed": []}

    for name, path in sources:
        success = run_script(name, path)
        if success:
            results["success"].append(name)
        else:
            results["failed"].append(name)

    # Mise à jour du dashboard
    print("\n" + "=" * 60)
    print("FIN DES EXTRACTIONS. Mise à jour du Dashboard...")
    if os.path.exists(MONITOR_SCRIPT):
        subprocess.run([sys.executable, MONITOR_SCRIPT], check=False)
    
    # Résumé
    print("\n" + "=" * 60)
    print(f"RÉSUMÉ FINAL")
    print(f"Total sources : {len(sources)}")
    print(f"Succès : {len(results['success'])}")
    print(f"Échecs : {len(results['failed'])}")
    if results["failed"]:
        print(f"Sources en erreur : {', '.join(results['failed'])}")
    print("=" * 60)

if __name__ == "__main__":
    main()
