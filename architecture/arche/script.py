from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python
from diagrams.custom import Custom
from diagrams.onprem.database import MongoDB

# Configuration globale du graphique avec une taille de police lisible et adaptative
graph_attr = {
    "fontsize": "32",          # Police principale plus grande pour le titre du diagramme
    "fontname": "Arial Bold",
    "bgcolor": "white",
    "nodesep": "1.0",          # Augmenté pour laisser de l'espace horizontal entre les blocs
    "ranksep": "2.0",          # Augmenté pour éviter les collisions verticales de flux
    "splines": "ortho",
}

# Style commun pour les sous-clusters (Pas de fond, texte agrandi et nœuds dynamiques)
cluster_attr = {
    "bgcolor": "transparent",
    "fontsize": "24",          # Agrandissement de la police des titres de chaque étape
    "fontname": "Arial Bold",
    "fixedsize": "false",      # Permet aux boîtes de s'adapter au texte
}

node_attr = {
    "fontsize": "22",
    "fontname": "Arial Bold"
}

edge_attr = {
    "fontsize": "20",
    "fontname": "Arial Bold"
}

with Diagram(
    "CTI Pipeline Architecture - BlueSec SOC",
    show=False,
    filename="cti_final_schema",
    direction="TB",
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
    with Cluster("Extraction IOC & CVE", graph_attr=cluster_attr):
        extraction = Python("", width="2.0", height="2.0")

    # 4. ENRICHISSEMENT
    with Cluster("Enrichissement Multi-couches", graph_attr=cluster_attr):
        with Cluster("Geolocalisation", graph_attr=cluster_attr):
            geo = Custom("", "./logos/geolocalisatiion_ip.png")

        with Cluster("URLScan.io", graph_attr=cluster_attr):
            urlscan = Custom("", "./logos/urlscan.png")

        with Cluster("VirusTotal", graph_attr=cluster_attr):
            vt_enr = Custom("", "./logos/VT.png")

        with Cluster("AbuseIPDB", graph_attr=cluster_attr):
            abuse_enr = Custom("", "./logos/Abuse.png")

    # 5. NORMALISATION
    with Cluster("Normalisation & Deduplication\nStandardize", graph_attr=cluster_attr):
        normalise = Python("", width="2.0", height="2.0")

    # 6. MISP
    with Cluster("MISP\n- Partage\n- Correlation", graph_attr=cluster_attr):
        misp = Custom("", "./logos/MISP.png")

    # 7. BULLETIN
    with Cluster("Communication\n- Rapports SOC", graph_attr=cluster_attr):
        bulletin = Custom("", "./logos/Bulteinsecuitre.png")

    # ─────────────────────────────────────────────────────────────────────────
    # BRANCHE TELEGRAM  (module leak_data_integration)
    # ─────────────────────────────────────────────────────────────────────────

    # T1. Sources Telegram
    with Cluster("Sources Telegram\n(Canaux Hacktivistes)", graph_attr=cluster_attr):
        tg_ch1 = Custom("Jabaroot DZ", "./logos/Telegram.png")
        tg_ch2 = Custom("Canal Privé",  "./logos/Telegram.png")

    # T2. Collecte Telethon
    with Cluster("Collecte Telegram\n(TelegramCollector)", graph_attr=cluster_attr):
        tg_collect = Python("", width="2.0", height="2.0")

    # T3. Analyse LLM  ─ is_leak / severity / leak_type
    with Cluster("Analyse & Détection\n(LeakAnalyzer + LLM)", graph_attr=cluster_attr):
        tg_analyze = Python("", width="2.0", height="2.0")

    # T4. Corrélation IA
    with Cluster("Corrélation IA", graph_attr=cluster_attr):
        tg_correlate = Python("", width="2.0", height="2.0")

    # T5. Intel Store  (leaks_intel.json)
    with Cluster("Intelligence Store\n(leaks_intel.json)", graph_attr=cluster_attr):
        tg_intel = Python("", width="2.0", height="2.0")

    # ─────────────────────────────────────────────────────────────────────────
    # FLUX  —  Pipeline CTI classique (Polices de flèches à fontsize=11 pour rester lisible)
    # ─────────────────────────────────────────────────────────────────────────
    for src in sources:
        src >> Edge(color="steelblue") >> collecte

    collecte   >> Edge(color="steelblue")                                >> extraction
    extraction >> Edge(color="blue")                                     >> geo
    extraction >> Edge(color="purple", style="dashed", label="URLs / Domains", fontsize="20", fontname="Arial Bold")  >> urlscan
    extraction >> Edge(color="blue",   style="dashed", label="Hashes / URLs\nDomains / IPs", fontsize="20", fontname="Arial Bold")  >> vt_enr
    extraction >> Edge(color="blue",   style="dashed", label="IPs", fontsize="20", fontname="Arial Bold")   >> abuse_enr

    geo     >> Edge(color="blue")   >> normalise
    urlscan >> Edge(color="purple") >> normalise
    vt_enr  >> Edge(color="blue")   >> normalise
    abuse_enr >> Edge(color="blue")  >> normalise

    normalise >> Edge(color="green") >> misp
    misp      >> Edge(color="green") >> bulletin

    # ─────────────────────────────────────────────────────────────────────────
    # FLUX  —  Pipeline Telegram Leak
    # ─────────────────────────────────────────────────────────────────────────
    tg_ch1 >> Edge(color="#0088cc", style="bold")                        >> tg_collect
    tg_ch2 >> Edge(color="#0088cc", style="bold")                        >> tg_collect

    tg_collect   >> Edge(color="#0088cc", label="Messages + Fichiers", fontsize="20", fontname="Arial Bold")   >> tg_analyze
    tg_analyze   >> Edge(color="darkorange", label="Leaks confirmés", fontsize="20", fontname="Arial Bold")     >> tg_correlate
    tg_correlate >> Edge(color="darkorange", label="Incidents consolidés", fontsize="20", fontname="Arial Bold") >> tg_intel

    # Les données Telegram NE passent PAS par MISP
    tg_intel >> Edge(color="darkorange", style="bold", label="Rapports SOC", fontsize="22", fontname="Arial Bold") >> bulletin

print("Schema genere avec succes")