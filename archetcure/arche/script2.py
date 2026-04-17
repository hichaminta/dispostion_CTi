from diagrams import Diagram
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python
from diagrams.custom import Custom

graph_attr = {
    "fontsize": "16",
    "bgcolor": "white",
    "nodesep": "0.6",
    "ranksep": "1.3",
}

with Diagram(
    "CTI Architecture",
    show=False,
    filename="cti_schema",
    direction="LR",
    graph_attr=graph_attr
):

    # --- SOURCES ---
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

    # --- MISP ---
    misp = Blank("MISP")

    # --- BULLETIN (AVEC TON LOGO) ---
    bulletin = Custom("Bulletin CTI", "bulletin.png")

    # --- FLOW ---
    for s in sources:
        s >> collecte

    collecte >> extraction >> dedup >> structuration >> misp >> bulletin

print("Schéma avec logo généré !")