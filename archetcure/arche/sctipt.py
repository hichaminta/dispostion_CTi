from diagrams import Diagram
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "nodesep": "0.6",
    "ranksep": "1.3",
}

with Diagram(
    "CTI Architecture for SOC",
    show=False,
    filename="cti_final_schema",
    direction="LR",
    graph_attr=graph_attr
):

    # --- SOURCES (SANS BACKGROUND, 5 SEULEMENT) ---
    vt = Blank("VirusTotal")
    otx = Blank("OTX")
    nist = Blank("NIST")
    abuse = Blank("Abuse.ch")
    phish = Blank("PhishTank")

    sources = [vt, otx, nist, abuse, phish]

    # --- COLLECTE ---
    collecte = Python("Collecte\nAPI / Scraping")

    # --- EXTRACTION ---
    extraction = Python("Extraction CTI\nIOC & CVE")

    # --- ANALYSE ---
    dedup = Python("Déduplication")
    structuration = Python("Structuration")

    dedup >> structuration

    # --- MISP ---
    misp = Blank("MISP")

    # --- COMMUNICATION ---
    bulletin = Blank("Bulletins")

    # --- CONNEXIONS ---
    for s in sources:
        s >> collecte

    collecte >> extraction >> dedup
    structuration >> misp
    misp >> bulletin

print("Schéma final généré")