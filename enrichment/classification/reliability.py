
class SourceReliability:
    """Gère les niveaux de confiance pour les différentes sources CTI."""
    
    # Scores de fiabilité par source (0-100)
    SOURCE_RELIABILITY = {
        "nvd": 100,            # Source officielle
        "spamhaus": 95,        # Très haute fiabilité
        "malwarebazaar": 95,   # Confirmé par analyse de fichiers
        "threatfox": 90,       # Confirmé par la communauté
        "feodotracker": 90,    # Spécialisé botnets
        "abuseipdb": 85,       # Fiable mais basé sur rapports utilisateurs
        "urlhaus": 80,         # Très réactif
        "alienvault": 75,      # OTX peut contenir du bruit
        "cins_army": 75,       # Listes de blocage IP
        "phishtank": 70,       # Beaucoup de faux positifs potentiels
        "openphish": 70,       # Similaire à PhishTank
        "pulsedive": 70        # Agrégateur
    }

    @staticmethod
    def get_confidence(source_name):
        """Retourne un score de confiance pour une source donnée."""
        return SourceReliability.SOURCE_RELIABILITY.get(source_name.lower(), 50)

    @staticmethod
    def apply_reliability_tag(record, source_name):
        """Applique un tag de fiabilité basé sur la source."""
        conf = SourceReliability.get_confidence(source_name)
        if conf >= 90:
            tag = "reliability:high"
        elif conf >= 75:
            tag = "reliability:medium"
        else:
            tag = "reliability:low"
            
        if "tags" not in record:
            record["tags"] = []
        if tag not in record["tags"]:
            record["tags"].append(tag)
        record["source_confidence"] = conf
