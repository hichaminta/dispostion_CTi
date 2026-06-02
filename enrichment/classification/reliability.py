class SourceReliability:
    """Niveaux de confiance pour chaque source CTI."""

    SOURCE_RELIABILITY = {
        # Sources officielles / vérifiées
        "dfir_report":  100,   # Rapports DFIR profonds, très haute fiabilité
        "dfir":         100,
        "nvd":          100,   # NIST National Vulnerability Database
        "spamhaus":      95,   # Réputation très haute, peu de faux positifs
        "malwarebazaar": 95,   # Samples confirmés par analyse binaire
        "threatfox":     90,   # Communauté abuse.ch, bien modérée
        "feodotracker":  90,   # Spécialisé C2 botnets, très précis
        "abuseipdb":     85,   # Fiable mais basé sur rapports users
        "urlhaus":       80,   # Très réactif, quelques faux positifs
        "alienvault":    75,   # OTX peut contenir du bruit communautaire
        "cins":          75,   # Listes de blocage IP
        "cins_army":     75,
        "phishtank":     70,   # Votes communautaires, faux positifs possibles
        "openphish":     70,   # Feed automatique, moins vérifié
        "pulsedive":     70,   # Agrégateur, qualité variable
    }

    @staticmethod
    def get_confidence(source_name: str) -> int:
        key = source_name.lower().replace("-", "_")
        # Cherche une correspondance partielle si clé exacte absente
        for k, v in SourceReliability.SOURCE_RELIABILITY.items():
            if k in key or key in k:
                return v
        return 50  # source inconnue

    @staticmethod
    def apply_reliability_tag(record: dict, source_name: str):
        """Ajoute le tag reliability:X et source_confidence au record."""
        conf = SourceReliability.get_confidence(source_name)

        if conf >= 90:
            tag = "reliability:high"
        elif conf >= 75:
            tag = "reliability:medium"
        else:
            tag = "reliability:low"

        record.setdefault("tags", [])
        if tag not in record["tags"]:
            record["tags"].append(tag)

        record["source_confidence"] = conf