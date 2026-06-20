from diagrams import Diagram, Cluster, Edge
from diagrams.programming.language import Python
from diagrams.custom import Custom

graph_attr = {
    "fontsize": "48",
    "fontname": "Arial Bold",
    "fontcolor": "#1a3a6b",
    "bgcolor": "#EEF4FF",
    "nodesep": "1.2",
    "ranksep": "2.5",
    "splines": "ortho",
    "rankdir": "LR",
}

cluster_attr = {
    "bgcolor": "transparent",
    "fontsize": "32",
    "fontname": "Arial Bold",
    "fontcolor": "#1a3a6b",
    "fixedsize": "false",
}

node_attr = {
    "fontsize": "30",
    "fontname": "Arial Bold",
    "fontcolor": "#1a3a6b",
    "fixedsize": "false",
}

edge_attr = {
    "fontsize": "26",
    "fontname": "Arial Bold",
    "fontcolor": "#1a3a6b",
}

with Diagram(
    "Pipeline CTI Classique — BlueSec SOC",
    show=False,
    filename="pipeline_cti_classique",
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # 1. SOURCES
    with Cluster("Sources CTI", graph_attr=cluster_attr):
        with Cluster("OTX AlienVault", graph_attr=cluster_attr):
            otx   = Custom("", "./logos/ALienVT.png")
        with Cluster("NVD / NIST", graph_attr=cluster_attr):
            nist  = Custom("", "./logos/NVD.png")
        with Cluster("Abuse.ch", graph_attr=cluster_attr):
            abuse = Custom("", "./logos/Abuse.png")
        with Cluster("PhishTank", graph_attr=cluster_attr):
            phish = Custom("", "./logos/phisingtank.png")

    sources = [otx, nist, abuse, phish]

    # 2. COLLECTE
    with Cluster("Collecte\nAPI / Scraping", graph_attr=cluster_attr):
        collecte = Python("", width="2.0", height="2.0")

    # 3. EXTRACTION
    with Cluster("Extraction\nIOC et CVE", graph_attr=cluster_attr):
        extraction = Python("", width="2.0", height="2.0")

    # 4. ENRICHISSEMENT
    with Cluster("Enrichissement Multi-couches", graph_attr=cluster_attr):
        with Cluster("Géolocalisation", graph_attr=cluster_attr):
            geo = Custom("", "./logos/geolocalisatiion_ip.png")
        with Cluster("URLScan.io", graph_attr=cluster_attr):
            urlscan = Custom("", "./logos/urlscan.png")
        with Cluster("VirusTotal", graph_attr=cluster_attr):
            vt_enr = Custom("", "./logos/VT.png")
        with Cluster("AbuseIPDB", graph_attr=cluster_attr):
            abuse_enr = Custom("", "./logos/Abuse.png")

    # 5. CORRÉLATION & STIX
    with Cluster("Corrélation et\nStandardisation STIX", graph_attr=cluster_attr):
        normalise = Python("", width="2.0", height="2.0")

    # 6. MISP
    with Cluster("MISP\n- Partage", graph_attr=cluster_attr):
        misp = Custom("", "./logos/MISP.png")

    # 7. BULLETIN
    with Cluster("Communication\n- Rapports SOC", graph_attr=cluster_attr):
        bulletin = Custom("", "./logos/Bulteinsecuitre.png")

    # FLUX
    for src in sources:
        src >> Edge(color="steelblue") >> collecte

    collecte >> Edge(color="steelblue") >> extraction

    extraction >> Edge(color="blue",   style="dashed", label="IPs",                fontsize="28", fontname="Arial Bold") >> geo
    extraction >> Edge(color="purple", style="dashed", label="URLs / Domains",     fontsize="28", fontname="Arial Bold") >> urlscan
    extraction >> Edge(color="blue",   style="dashed", label="Hashes / URLs / IPs",fontsize="28", fontname="Arial Bold") >> vt_enr
    extraction >> Edge(color="blue",   style="dashed", label="IPs",                fontsize="28", fontname="Arial Bold") >> abuse_enr

    geo       >> Edge(color="blue")   >> normalise
    urlscan   >> Edge(color="purple") >> normalise
    vt_enr    >> Edge(color="blue")   >> normalise
    abuse_enr >> Edge(color="blue")   >> normalise

    normalise >> Edge(color="green") >> misp
    misp      >> Edge(color="green") >> bulletin

print("pipeline_cti_classique.png généré avec succès")