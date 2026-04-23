import json
import os
from datetime import datetime

def convert_to_misp(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        records = json.load(f)

    misp_events = []

    for record in records:
        source = record.get("source", "Unknown")
        collected_at = record.get("collected_at", "")
        try:
            event_date = datetime.fromisoformat(collected_at.replace('Z', '+00:00')).strftime("%Y-%m-%d")
        except:
            event_date = datetime.now().strftime("%Y-%m-%d")

        # Basic Event Structure
        event = {
            "info": f"CTI Source: {source.capitalize()}",
            "date": event_date,
            "threat_level_id": "2",
            "analysis": "0",
            "distribution": "0",
            "Attribute": [],
            "Object": [],
            "Tag": []
        }

        # Add Source Tag
        event["Tag"].append({"name": f"source:{source.lower()}"})

        # Process IOCs
        for ioc in record.get("iocs", []):
            ioc_type = ioc.get("type", "").replace("domaine", "domain")
            ioc_value = ioc.get("value", "")
            enrichment = ioc.get("ioc_enrichment", {})

            # Confidence calculation (Bonus)
            relevant_fields = ["asn", "country", "malware_family", "status", "hostname"]
            richness = sum(1 for field in relevant_fields if enrichment.get(field))
            confidence = int((richness / len(relevant_fields)) * 100)

            # MISP Object
            misp_obj = {
                "name": "indicator",
                "meta-category": "misc",
                "description": f"Indicator for {ioc_value}",
                "Attribute": []
            }

            # Map type and relation
            m_type = "ip-dst" if ioc_type == "ip" else ioc_type
            m_rel = "ip" if ioc_type == "ip" else "domain"

            # Main Attribute
            main_attr = {
                "type": m_type,
                "value": ioc_value,
                "object_relation": m_rel,
                "to_ids": True,
                "comment": f"Confidence: {confidence}%",
                "Tag": []
            }

            # Add enrichment to tags/comments
            if enrichment.get("malware_family"):
                family = enrichment["malware_family"].lower()
                main_attr["Tag"].append({"name": f"malware:{family}"})
            
            if enrichment.get("status"):
                status = enrichment["status"].lower()
                main_attr["Tag"].append({"name": f"status:{status}"})

            # Additional metadata in comment
            meta_info = []
            if enrichment.get("asn"): meta_info.append(f"ASN: {enrichment['asn']}")
            if enrichment.get("country"): meta_info.append(f"Country: {enrichment['country']}")
            if enrichment.get("hostname") and enrichment["hostname"] != ioc_value:
                meta_info.append(f"Hostname: {enrichment['hostname']}")
            
            if meta_info:
                main_attr["comment"] += " | " + " | ".join(meta_info)

            misp_obj["Attribute"].append(main_attr)
            event["Object"].append(misp_obj)

        misp_events.append({"Event": event})

    return misp_events

if __name__ == "__main__":
    input_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\output_normaliser\run_2026_04_22_205043\feodotracker_normalized.json"
    output = convert_to_misp(input_path)
    print(json.dumps(output, indent=2))
