import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import sys
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cti_db")

def init_db():
    print("=========================================")
    print("Initialisation de la connexion MongoDB...")
    print(f"URI: {MONGO_URI}")
    print(f"Database: {MONGO_DB_NAME}")
    print("=========================================\n")

    try:
        # Essayer de se connecter
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        
        # Vérifier si le serveur répond
        client.admin.command('ping')
        print("[OK] Connexion a MongoDB reussie !")

        # Accéder à la base de données
        db = client[MONGO_DB_NAME]
        
        # Vérifier / Créer les collections par défaut
        collections = db.list_collection_names()
        print(f"Collections existantes : {collections}")

        if "runs" not in collections:
            db.create_collection("runs")
            print("[OK] Collection 'runs' creee ou prete.")
        else:
            print("[OK] Collection 'runs' deja existante.")

        if "schedules" not in collections:
            db.create_collection("schedules")
            print("[OK] Collection 'schedules' creee ou prete.")
        else:
            print("[OK] Collection 'schedules' deja existante.")

        print("\nVotre base MongoDB est prête à être utilisée par le projet CTI !")
    except ConnectionFailure as e:
        print("[Erreur] Impossible de se connecter a MongoDB.")
        print(f"Details: {e}")
        print("Verifiez que votre conteneur Docker MongoDB est bien en cours d'execution.")
        sys.exit(1)
    except Exception as e:
        print(f"[Erreur] Une erreur inattendue est survenue : {e}")
        sys.exit(1)

if __name__ == "__main__":
    init_db()
