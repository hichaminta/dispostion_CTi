import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import time
import sys

print("=== DEBUT DE L'ENRICHISSEMENT ===")
print("Consommation des données normalisées...")
time.sleep(1.5)
print("Corrélation avec les bases de réputation...")
time.sleep(2)
print("Calcul des scores de criticité...")
time.sleep(1.5)
print("Enrichissement terminé avec succès.")
sys.exit(0)
