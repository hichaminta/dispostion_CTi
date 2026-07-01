import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import subprocess
import os

def run_platform():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    deployer_dir = os.path.join(base_dir, "deployer")
    
    print("="*50)
    print("Lancement de la plateforme CTI via Docker Compose...")
    print("="*50)
    
    print(f"Dossier de déploiement : {deployer_dir}")
    print("Reconstruction des images et démarrage des conteneurs...\n")
    
    try:
        # Lancer docker-compose up avec l'affichage des logs en temps réel
        subprocess.run(
            ["docker-compose", "up", "--build"],
            cwd=deployer_dir
        )
    except KeyboardInterrupt:
        print("\nArrêt demandé par l'utilisateur (Ctrl+C)...")
        print("Nettoyage des conteneurs Docker...")
        subprocess.run(
            ["docker-compose", "down"],
            cwd=deployer_dir
        )
        print("Plateforme arrêtée avec succès.")

if __name__ == "__main__":
    run_platform()
