from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python
from diagrams.custom import Custom

# Configuration du graphique
graph_attr = {
    "fontsize": "15",
    "bgcolor": "white",
    "nodesep": "0.6",
    "ranksep": "1.4",
    "splines": "ortho",
}

# Style commun pour les clusters (pas de fond, seulement bordures)
cluster_attr = {
    "bgcolor": "transparent",
}

with Diagram(
    "CTI Pipeline Architecture - BlueSec SOC",
    show=False,
    filename="cti_final_schema",
    direction="LR",
    graph_attr=graph_attr,
):

    # 1. SOURCES
    with Cluster("Sources CTI", graph_attr=cluster_attr):
        with Cluster("VirusTotal", graph_attr=cluster_attr):
            vt    = Custom("", "./logos/VT.png")
        with Cluster("OTX AlienVault", graph_attr=cluster_attr):
            otx   = Custom("", "./logos/ALienVT.png")
        with Cluster("NVD / NIST", graph_attr=cluster_attr):
            nist  = Custom("", "./logos/NVD.png")
        with Cluster("Abuse.ch", graph_attr=cluster_attr):
            abuse = Custom("", "./logos/Abuse.png")
        with Cluster("PhishTank", graph_attr=cluster_attr):
            phish = Custom("", "./logos/phisingtank.png")

    sources = [vt, otx, nist, abuse, phish]

    # 2. COLLECTE
    with Cluster("Collecte\nAPI / Scraping", graph_attr=cluster_attr):
        collecte = Python("", width="2.0", height="2.0")

    # 3. EXTRACTION
    with Cluster("Extraction IOC & CVE", graph_attr=cluster_attr):
        extraction = Python("", width="2.0", height="2.0")

    # 4. ENRICHISSEMENT
    with Cluster("Enrichissement Multi-couches", graph_attr=cluster_attr):
        with Cluster("NLP (NLTK + Regex)", graph_attr=cluster_attr):
            nlp = Python("", width="2.0", height="2.0")

        with Cluster("Geolocalisation", graph_attr=cluster_attr):
            geo = Custom("", "./logos/geolocalisatiion_ip.png")

        with Cluster("URLScan.io", graph_attr=cluster_attr):
            urlscan = Custom("", "./logos/urlscan.png")

    # 5. NORMALISATION
    with Cluster("Normalisation & Deduplication\nStandardize", graph_attr=cluster_attr):
        normalise = Python("", width="2.0", height="2.0")

    # 6. MISP
    with Cluster("MISP\n- Partage\n- Correlation", graph_attr=cluster_attr):
        misp = Custom("", "./logos/MISP.png")

    # 7. BULLETIN
    with Cluster("Communication\n- Rapports SOC", graph_attr=cluster_attr):
        bulletin = Custom("", "./logos/Bulteinsecuitre.png")

    # FLUX
    for src in sources:
        src >> Edge(color="steelblue") >> collecte

    collecte >> Edge(color="steelblue") >> extraction
    extraction >> Edge(color="blue") >> nlp
    nlp >> Edge(color="blue") >> geo
    
    # URLScan suit maintenant le NLP
    nlp >> Edge(color="purple", style="dashed", label="URLs contextuelles") >> urlscan

    geo >> Edge(color="blue") >> normalise
    urlscan >> Edge(color="purple") >> normalise

    normalise >> Edge(color="green") >> misp
    misp >> Edge(color="green") >> bulletin

print("Schema genere avec succes")
