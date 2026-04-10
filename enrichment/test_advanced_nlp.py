import sys
import os
import json

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from enrichers.nlp_enricher import NLPEnricher

def test_enrichment():
    enricher = NLPEnricher()
    
    sample_items = [
        {
            "id": "1.2.3.4",
            "indicator": "1.2.3.4",
            "source": "Manual",
            "raw_text": "The threat actor known as APT28 is attacking Windows systems in Germany using the Cobalt Strike malware family. They are targeting government organizations in Berlin.",
            "summary": "Active attack from Russia.",
            "tags": []
        },
        {
            "indicator": "CVE-2023-1234",
            "source": "NVD",
            "raw_text": "A critical vulnerability CVE-2023-1234 was found in Apache Struts. Affected users should patch immediately. This exploit is being used by Lazarus Group.",
            "summary": "Vulnerability in Apache.",
            "tags": ["vulnerability"]
        }
    ]
    
    print("Starting NLP Enrichment Test...\n")
    
    for item in sample_items:
        print(f"--- Processing Indicator: {item.get('indicator')} ---")
        enriched = enricher.enrich(item)
        
        print(f"Tags: {enriched.get('tags')}")
        print(f"NLP Advanced Metadata:")
        print(json.dumps(enriched['enrichment']['nlp_advanced'], indent=2))
        if 'nlp_summary' in enriched['enrichment']:
            print(f"Summary: {enriched['enrichment']['nlp_summary']}")
        print("\n")

if __name__ == "__main__":
    test_enrichment()
