import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
class SourceReliability:
    """Niveaux de confiance pour chaque source CTI."""

    SOURCE_RELIABILITY = {
        # Sources officielles / vÃ©rifiÃ©es
        "dfir_report":  100,   # Rapports DFIR profonds, trÃ¨s haute fiabilitÃ©
        "dfir":         100,
        "nvd":          100,   # NIST National Vulnerability Database
        "spamhaus":      95,   # RÃ©putation trÃ¨s haute, peu de faux positifs
        "malwarebazaar": 95,   # Samples confirmÃ©s par analyse binaire
        "threatfox":     90,   # CommunautÃ© abuse.ch, bien modÃ©rÃ©e
        "feodotracker":  90,   # SpÃ©cialisÃ© C2 botnets, trÃ¨s prÃ©cis
        "abuseipdb":     85,   # Fiable mais basÃ© sur rapports users
        "urlhaus":       80,   # TrÃ¨s rÃ©actif, quelques faux positifs
        "alienvault":    75,   # OTX peut contenir du bruit communautaire
        "cins":          75,   # Listes de blocage IP
        "cins_army":     75,
        "phishtank":     70,   # Votes communautaires, faux positifs possibles
        "openphish":     70,   # Feed automatique, moins vÃ©rifiÃ©
        "pulsedive":     70,   # AgrÃ©gateur, qualitÃ© variable
    }

    @staticmethod
    def get_confidence(source_name: str) -> int:
        key = source_name.lower().replace("-", "_")
        # Cherche une correspondance partielle si clÃ© exacte absente
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