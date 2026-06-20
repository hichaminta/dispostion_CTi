from diagrams import Diagram, Cluster, Edge
from diagrams.programming.language import Python
from diagrams.custom import Custom

graph_attr = {
    "fontsize": "48",
    "fontname": "Arial Bold",
    "fontcolor": "#7a3a00",
    "bgcolor": "#FFF8EE",
    "nodesep": "1.2",
    "ranksep": "2.5",
    "splines": "ortho",
    "rankdir": "LR",
}

cluster_attr = {
    "bgcolor": "transparent",
    "fontsize": "32",
    "fontname": "Arial Bold",
    "fontcolor": "#7a3a00",
    "fixedsize": "false",
}

node_attr = {
    "fontsize": "30",
    "fontname": "Arial Bold",
    "fontcolor": "#7a3a00",
    "fixedsize": "false",
}

edge_attr = {
    "fontsize": "26",
    "fontname": "Arial Bold",
    "fontcolor": "#7a3a00",
}

with Diagram(
    "Pipeline Telegram Leak — BlueSec SOC",
    show=False,
    filename="pipeline_telegram_leak",
    direction="LR",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # T1. Sources Telegram
    with Cluster("Sources Telegram\n(Canaux Hacktivistes)", graph_attr=cluster_attr):
        tg_ch1 = Custom("Jabaroot DZ", "./logos/Telegram.png")
        tg_ch2 = Custom("Canal Privé",  "./logos/Telegram.png")

    # T2. Collecte Telethon
    with Cluster("Collecte Telegram\n(TelegramCollector)", graph_attr=cluster_attr):
        tg_collect = Python("", width="2.0", height="2.0")

    # T3. Analyse LLM
    with Cluster("Analyse et Détection\n(LeakAnalyzer + LLM)", graph_attr=cluster_attr):
        tg_analyze = Python("", width="2.0", height="2.0")

    # T4. Corrélation IA
    with Cluster("Corrélation IA", graph_attr=cluster_attr):
        tg_correlate = Python("", width="2.0", height="2.0")

    # T5. Intel Store
    with Cluster("Intelligence Store\n(leaks_intel.json)", graph_attr=cluster_attr):
        tg_intel = Python("", width="2.0", height="2.0")

    # T6. Bulletin SOC
    with Cluster("Communication\n- Rapports SOC", graph_attr=cluster_attr):
        bulletin = Custom("", "./logos/Bulteinsecuitre.png")

    # FLUX
    tg_ch1 >> Edge(color="#0088cc", style="bold") >> tg_collect
    tg_ch2 >> Edge(color="#0088cc", style="bold") >> tg_collect

    tg_collect   >> Edge(color="#0088cc",    label="Messages + Fichiers",  fontsize="28", fontname="Arial Bold") >> tg_analyze
    tg_analyze   >> Edge(color="darkorange", label="Leaks confirmés",      fontsize="28", fontname="Arial Bold") >> tg_correlate
    tg_correlate >> Edge(color="darkorange", label="Incidents consolidés", fontsize="28", fontname="Arial Bold") >> tg_intel
    tg_intel     >> Edge(color="darkorange", style="bold", label="Rapports SOC", fontsize="28", fontname="Arial Bold") >> bulletin

print("pipeline_telegram_leak.png généré avec succès")