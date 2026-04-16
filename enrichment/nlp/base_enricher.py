import logging

class BaseEnricher:
    """Base class for all IOC enrichers."""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"Enricher.{self.name}")

    def enrich(self, data: dict) -> dict:
        """
        Enriches a single IOC item or list of items.
        
        Args:
            data (dict): The raw dictionary representing an IOC or CVE.
        
        Returns:
            dict: The enriched dictionary.
        """
        raise NotImplementedError("Subclasses must implement the 'enrich' method.")
