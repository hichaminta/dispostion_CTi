from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python
from diagrams.custom import Custom
from diagrams.onprem.database import MongoDB

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
    with Cluster("Corrélation IA\n(DailyCorrelator)", graph_attr=cluster_attr):
        tg_correlate = Python("", width="2.0", height="2.0")

    # T5. Intel Store  (leaks_intel.json)
    with Cluster("Intelligence Store\n(leaks_intel.json)", graph_attr=cluster_attr):
        tg_intel = Python("", width="2.0", height="2.0")

    # ─────────────────────────────────────────────────────────────────────────
    # FLUX  —  Pipeline CTI classique
    # ─────────────────────────────────────────────────────────────────────────
    for src in sources:
        src >> Edge(color="steelblue") >> collecte

    collecte   >> Edge(color="steelblue")                        >> extraction
    extraction >> Edge(color="blue")                             >> geo
    extraction >> Edge(color="purple", style="dashed", label="URLs / Domains")  >> urlscan
    extraction >> Edge(color="blue",   style="dashed", label="Hashes / URLs / Domains")  >> vt_enr
    extraction >> Edge(color="blue",   style="dashed", label="IPs")   >> abuse_enr

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

    tg_collect   >> Edge(color="#0088cc", label="Messages + Fichiers")   >> tg_analyze
    tg_analyze   >> Edge(color="darkorange", label="Leaks confirmés")     >> tg_correlate
    tg_correlate >> Edge(color="darkorange", label="Incidents consolidés") >> tg_intel

    # Les données Telegram NE passent PAS par MISP (leaks_intel.json ≠ output_correlation/)
    # Elles alimentent uniquement les rapports / bulletins SOC
    tg_intel >> Edge(color="gray", style="dashed", label="Rapports SOC") >> bulletin

print("Schema genere avec succes")
