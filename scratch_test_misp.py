import os
import json
from pymisp import PyMISP, MISPEvent
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("MISP_URL")
key = os.getenv("MISP_KEY")

print(f"Tentative de connexion à {url}...")

try:
    misp = PyMISP(url, key, False, debug=False)
    print("Connexion réussie.")
    
    event = MISPEvent()
    event.info = "Test Permission Admin"
    
    print("Tentative de création d'un événement de test...")
    result = misp.add_event(event)
    
    if "errors" in result:
        print(f"ERREUR MISP : {result['errors']}")
    else:
        print(f"SUCCÈS ! Événement créé avec l'ID : {result['Event']['id']}")
        # On le supprime tout de suite pour nettoyer
        misp.delete_event(result['Event']['id'])
        print("Événement de test supprimé.")

except Exception as e:
    print(f"ERREUR CRITIQUE : {e}")
