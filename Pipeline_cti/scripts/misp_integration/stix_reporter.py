import json
import os
import sys
import re
from datetime import datetime, timezone

# Force UTF-8 stdout on Windows to avoid cp1252 UnicodeEncodeError
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OUTPUT_FILE = os.path.join(BASE_DIR, "Pipeline_cti", "global_output", "output_correlation", "stix_export.json")

# MITRE ATT&CK ID to Tactic and Name mapping for enrichment
MITRE_NAMES = {
    "T1566": ("Initial Access", "Phishing"),
    "T1566.001": ("Initial Access", "Spearphishing Attachment"),
    "T1497": ("Defense Evasion", "Virtualization/Sandbox Evasion"),
    "T1071.001": ("Command &amp; Control", "Web Protocols (HTTP/S C2)"),
    "T1059.001": ("Execution", "PowerShell"),
    "T1059.007": ("Execution", "JavaScript"),
    "T1059.005": ("Execution", "Visual Basic"),
    "T1105": ("Command &amp; Control", "Ingress Tool Transfer"),
    "T1204": ("Execution", "User Execution"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1071": ("Command &amp; Control", "Application Layer Protocol"),
    "TA0002": ("Execution", "Execution"),
    "TA0006": ("Credential Access", "Credential Access"),
    "TA0010": ("Exfiltration", "Exfiltration"),
    "TA0003": ("Persistence", "Persistence"),
    "TA0011": ("Command &amp; Control", "Command and Control"),
    "T1047": ("Execution", "Windows Management Instrumentation"),
    "T1055": ("Defense Evasion", "Process Injection"),
    "T1570": ("Lateral Movement", "Lateral Tool Transfer"),
    "T1083": ("Discovery", "File and Directory Discovery"),
    "T1078": ("Defense Evasion", "Valid Accounts"),
    "T1210": ("Lateral Movement", "Exploitation of Remote Services"),
    "T1068": ("Privilege Escalation", "Exploitation for Privilege Escalation"),
    "T1090": ("Command &amp; Control", "Proxy"),
    "T1555": ("Credential Access", "Credentials from Password Stores"),
    "T1583.001": ("Resource Development", "Acquire Infrastructure: Domains"),
    "T1498": ("Impact", "Network Denial of Service"),
    "T1499": ("Impact", "Endpoint Denial of Service"),
}

def parse_pattern(pattern):
    """Extrait le type et la valeur d'un indicateur STIX depuis son pattern."""
    if not pattern:
        return "Unknown", ""
    # IP
    m = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
    if m: return "IP", m.group(1)
    # Domain
    m = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
    if m: return "Domain", m.group(1)
    # URL
    m = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
    if m: return "URL", m.group(1)
    # Email
    m = re.search(r"email-addr:value\s*=\s*'([^']+)'", pattern)
    if m: return "Email", m.group(1)
    # File hashes (supports optionally quoted hash types)
    m = re.search(r"file:hashes\.['\"]?[a-zA-Z0-9_-]+['\"]?\s*=\s*'([^']+)'", pattern)
    if m: return "Hash", m.group(1)
    
    return "Unknown", ""


class STIXReporter:
    """Génère un bulletin PDF de threat intelligence depuis le bundle STIX 2.1."""

    PRIORITY_COLORS = {
        "CRITICAL": (220, 38,  38),
        "HIGH":     (234, 88,  12),
        "MEDIUM":   (202, 138,  4),
        "LOW":      (37,  99, 235),
    }

    def __init__(self, input_file=None):
        self.base_dir    = BASE_DIR
        
        if input_file:
            self.input_file = input_file
        else:
            out_dir = os.path.join(self.base_dir, "Pipeline_cti", "global_output", "output_correlation")
            try:
                files = [f for f in os.listdir(out_dir) if f.startswith("stix_export_") and f.endswith(".json")]
                if not files:
                    self.input_file = os.path.join(out_dir, "stix_export.json")
                else:
                    self.input_file = max([os.path.join(out_dir, f) for f in files], key=os.path.getmtime)
            except Exception:
                self.input_file = os.path.join(out_dir, "stix_export.json")

        self.reports_dir = os.path.join(self.base_dir, "bultein_de_security")
        os.makedirs(self.reports_dir, exist_ok=True)

    def _load_events_from_stix(self):
        """Méthode de compatibilité descendante."""
        if not os.path.exists(self.input_file):
            return []
        with open(self.input_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
            
        events = []
        objects = bundle.get("objects", [])
        main_types = {"malware", "vulnerability", "campaign", "infrastructure"}
        
        for obj in objects:
            if obj.get("type") in main_types:
                event = {
                    "event_name": obj.get("name", "Unknown"),
                    "group_id": obj.get("x_soc_group_id", ""),
                    "event_type": obj.get("type"),
                    "attack_type": obj.get("type").title(),
                    "priority_score": obj.get("x_soc_priority", "LOW"),
                    "risk_score": obj.get("x_soc_risk", 0),
                    "soc_action": obj.get("x_soc_action", "monitor"),
                    "confidence_score": obj.get("confidence", 0),
                    "first_seen": obj.get("first_seen") or obj.get("created", ""),
                    "last_seen": obj.get("last_seen") or obj.get("modified", ""),
                    "iocs": [],
                    "tags": obj.get("labels", []),
                    "mitre_techniques": [ref["external_id"] for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"]
                }
                
                obj_id = obj.get("id")
                ioc_count = 0
                for rel in objects:
                    if rel.get("type") == "relationship" and rel.get("relationship_type") == "indicates" and rel.get("target_ref") == obj_id:
                        ioc_count += 1
                
                event["iocs"] = [None] * ioc_count
                
                for rep in objects:
                    if rep.get("type") == "report" and obj_id in rep.get("object_refs", []):
                        event["source_list"] = rep.get("x_soc_sources", [])
                        break
                        
                events.append(event)
                
        return events

    def generate_pdf(self, output_path: str = None, threat_filter_id: str = None) -> str | None:
        """Génère un bulletin de sécurité PDF professionnel de style AREPSCTR.

        Si threat_filter_id est fourni, génère un bulletin ciblé sur cette seule menace
        et ses IOCs associés via les relations STIX 'indicates'.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        except ImportError:
            print("[STIXReporter] reportlab non installé — installez avec: pip install reportlab")
            return None

        if not os.path.exists(self.input_file):
            print(f"[STIXReporter] Fichier bundle STIX introuvable: {self.input_file}")
            return None

        try:
            with open(self.input_file, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except Exception as e:
            print(f"[STIXReporter] Erreur lors du décodage du fichier STIX: {e}")
            return None

        objects = bundle.get("objects", [])
        if not objects:
            print("[STIXReporter] Aucun objet STIX trouvé dans le bundle.")
            return None

        # ── Triage et Extraction des Données ──────────────────────────────────
        main_types = {"malware", "vulnerability", "campaign", "infrastructure"}
        threats = [o for o in objects if o.get("type") in main_types]

        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threats_sorted = sorted(
            threats,
            key=lambda x: (priority_order.get(x.get("x_soc_priority", "LOW").upper(), 4), -x.get("x_soc_risk", 0.0))
        )

        # Si un filtre par threat est demandé, ne garder que ce threat
        if threat_filter_id:
            threats_sorted = [t for t in threats_sorted if t.get("id") == threat_filter_id]

        # Identification du threat principal pour l'exécutif résumé
        if threats_sorted:
            top_threat = threats_sorted[0]
        else:
            top_threat = {
                "name": "SOC STIX Import Event Bundle",
                "x_soc_priority": "LOW",
                "type": "indicator-bundle",
                "confidence": 100,
                "x_soc_action": "monitor",
                "attack_type": "Multi-source",
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat()
            }

        # ── Configuration du TLP et de la Classification ──────────────────────
        max_priority = top_threat.get("x_soc_priority", "LOW").upper()
        if max_priority in ["CRITICAL", "HIGH"]:
            tlp_text = "TLP:RED"
            tlp_color = colors.HexColor("#d32f2f")
            classif_text = "TLP:RED - Confidentiel"
        elif max_priority == "MEDIUM":
            tlp_text = "TLP:AMBER"
            tlp_color = colors.HexColor("#e65100")
            classif_text = "TLP:AMBER - Limité"
        else:
            tlp_text = "TLP:CLEAR"
            tlp_color = colors.HexColor("#555555")
            classif_text = "TLP:CLEAR - Public"

        # Période observée
        dates = []
        for obj in objects:
            for k in ["first_seen", "last_seen", "created", "modified", "valid_from"]:
                val = obj.get(k)
                if val:
                    try:
                        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                        dates.append(dt)
                    except ValueError:
                        pass
        if dates:
            observed_period = f"{min(dates).strftime('%Y-%m-%d')} \u2192 {max(dates).strftime('%Y-%m-%d')}"
        else:
            observed_period = "N/A"

        # Type de menace formaté
        threat_type_raw = top_threat.get("type", "Unknown")
        threat_type_map = {
            "campaign": "Campagne de Phishing",
            "malware": "Logiciel malveillant (Malware)",
            "vulnerability": "Exploitation de Vulnérabilité",
            "infrastructure": "Infrastructure malveillante"
        }
        threat_type_desc = threat_type_map.get(threat_type_raw, threat_type_raw.title())

        # Acteur suspecté
        actors = []
        for label in top_threat.get("labels", []):
            if label.startswith("actor:"):
                actors.append(label.split(":", 1)[1].title())
        suspected_actor = ", ".join(actors) if actors else (top_threat.get("x_soc_group_id") or "Inconnu")

        # ── Extraction et Tri des Indicateurs ───────────────────────────────
        indicators = [o for o in objects if o.get("type") == "indicator"]
        indicators_sorted = sorted(
            indicators,
            key=lambda x: (priority_order.get(x.get("x_ioc_priority", "LOW").upper(), 4), -x.get("x_ioc_risk_score", 0.0))
        )

        # Si filtre par threat : ne garder que les IOCs liés à ce threat via "indicates"
        if threat_filter_id:
            linked_ids = {
                rel.get("source_ref")
                for rel in objects
                if rel.get("type") == "relationship"
                and rel.get("relationship_type") == "indicates"
                and rel.get("target_ref") == threat_filter_id
            }
            indicators_sorted = [i for i in indicators_sorted if i.get("id") in linked_ids]

        # Chargement de la corrélation d'enrichissement si présente
        try:
            corr_dir = os.path.dirname(self.input_file)
            corr_files = [f for f in os.listdir(corr_dir) if f.startswith("correlation_file_") and f.endswith(".json")]
            if not corr_files:
                corr_file = os.path.join(corr_dir, "correlated_events_soc_enriched.json")
            else:
                corr_file = max([os.path.join(corr_dir, f) for f in corr_files], key=os.path.getmtime)
        except Exception:
            corr_file = os.path.join(os.path.dirname(self.input_file), "correlated_events_soc_enriched.json")
        corr_events = []
        if os.path.exists(corr_file):
            try:
                with open(corr_file, "r", encoding="utf-8") as f:
                    corr_events = json.load(f)
            except Exception as e:
                print(f"[STIXReporter] Warning: impossible de charger le fichier de corrélation: {e}")

        # ── Styles ReportLab ──────────────────────────────────────────────────
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            name='CtiSectionTitle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#17365d"),
            backColor=colors.HexColor("#f2f2f2"),
            borderPadding=4,
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True
        )
        
        cell_style = ParagraphStyle(
            name='CtiTableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#333333")
        )
        
        cell_bold_style = ParagraphStyle(
            name='CtiTableCellBold',
            parent=cell_style,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor("#17365d")
        )
        
        cell_header_style = ParagraphStyle(
            name='CtiTableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9.5,
            textColor=colors.whitesmoke,
            alignment=1
        )
        
        code_style = ParagraphStyle(
            name='CtiCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7,
            leading=8.5,
            textColor=colors.HexColor("#111111"),
            backColor=colors.HexColor("#f8f8fa"),
            borderPadding=6,
            spaceBefore=4,
            spaceAfter=4
        )

        # ── 1. Résumé Exécutif ───────────────────────────────────────────────
        _tbl_style = TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f9fafb")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ])

        t_threats_overview = None  # présent uniquement en mode consolidé

        if threat_filter_id:
            # ── Mode par threat : résumé ciblé ──────────────────────────────
            severity = top_threat.get("x_soc_priority", "LOW").upper()
            severity_hex = "#10b981" if severity == "LOW" else "#eab308" if severity == "MEDIUM" else "#f97316" if severity == "HIGH" else "#ef4444"
            summary_data = [
                [Paragraph("Campagne / Événement", cell_bold_style), Paragraph(top_threat.get("name", "Unknown"), cell_style)],
                [Paragraph("Sévérité", cell_bold_style), Paragraph(f"<font color='{severity_hex}'><b>{severity}</b></font>", cell_style)],
                [Paragraph("Type de menace", cell_bold_style), Paragraph(threat_type_desc, cell_style)],
                [Paragraph("Confidence", cell_bold_style), Paragraph(f"{top_threat.get('confidence', 0)} %", cell_style)],
                [Paragraph("Acteur suspecté", cell_bold_style), Paragraph(suspected_actor, cell_style)],
                [Paragraph("Vecteur", cell_bold_style), Paragraph(top_threat.get("attack_type", "Inconnu"), cell_style)],
                [Paragraph("Période observée", cell_bold_style), Paragraph(observed_period, cell_style)],
                [Paragraph("Impact SOC", cell_bold_style), Paragraph(top_threat.get("x_soc_action", "monitor").upper(), cell_style)],
            ]
            t_summary = Table(summary_data, colWidths=[5.0 * cm, 12.0 * cm])
            t_summary.setStyle(_tbl_style)

        else:
            # ── Mode consolidé : statistiques globales de la collection ──────
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for t in threats_sorted:
                p = t.get("x_soc_priority", "LOW").upper()
                counts[p] = counts.get(p, 0) + 1

            collection_date = (bundle.get("x_soc_export_date") or "")[:10] or "N/A"

            summary_data = [
                [Paragraph("Date de collection", cell_bold_style), Paragraph(collection_date, cell_style)],
                [Paragraph("Période observée", cell_bold_style), Paragraph(observed_period, cell_style)],
                [Paragraph("Total menaces", cell_bold_style), Paragraph(str(len(threats_sorted)), cell_style)],
                [Paragraph("CRITICAL / HIGH", cell_bold_style),
                 Paragraph(f"<font color='#ef4444'><b>{counts['CRITICAL']}</b></font>"
                           f"&nbsp;/&nbsp;<font color='#f97316'><b>{counts['HIGH']}</b></font>", cell_style)],
                [Paragraph("MEDIUM / LOW", cell_bold_style),
                 Paragraph(f"<font color='#eab308'><b>{counts['MEDIUM']}</b></font>"
                           f"&nbsp;/&nbsp;<font color='#10b981'><b>{counts['LOW']}</b></font>", cell_style)],
                [Paragraph("Total IOCs", cell_bold_style), Paragraph(str(len(indicators_sorted)), cell_style)],
                [Paragraph("TLP Classification", cell_bold_style), Paragraph(tlp_text, cell_style)],
                [Paragraph("Sévérité maximale", cell_bold_style),
                 Paragraph(f"<font color='{('#ef4444' if max_priority == 'CRITICAL' else '#f97316' if max_priority == 'HIGH' else '#eab308' if max_priority == 'MEDIUM' else '#10b981')}'>"
                           f"<b>{max_priority}</b></font>", cell_style)],
            ]
            t_summary = Table(summary_data, colWidths=[5.0 * cm, 12.0 * cm])
            t_summary.setStyle(_tbl_style)

            # Tableau de vue d'ensemble de toutes les menaces
            _hdr = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ])
            threat_rows = [[
                Paragraph("Menace", cell_header_style),
                Paragraph("Type", cell_header_style),
                Paragraph("Priorité", cell_header_style),
                Paragraph("Risk", cell_header_style),
                Paragraph("IOCs", cell_header_style),
                Paragraph("Action SOC", cell_header_style),
            ]]
            for t in threats_sorted:
                prio = t.get("x_soc_priority", "LOW").upper()
                prio_hex = "#10b981" if prio == "LOW" else "#eab308" if prio == "MEDIUM" else "#f97316" if prio == "HIGH" else "#ef4444"
                tid_ref = t.get("id")
                ioc_cnt = sum(
                    1 for rel in objects
                    if rel.get("type") == "relationship"
                    and rel.get("relationship_type") == "indicates"
                    and rel.get("target_ref") == tid_ref
                )
                threat_rows.append([
                    Paragraph(t.get("name", "—")[:55], cell_style),
                    Paragraph(t.get("type", "—").title(), cell_style),
                    Paragraph(f"<font color='{prio_hex}'><b>{prio}</b></font>", cell_style),
                    Paragraph(f"{t.get('x_soc_risk', 0.0):.1f}", cell_style),
                    Paragraph(str(ioc_cnt), cell_style),
                    Paragraph(t.get("x_soc_action", "monitor").upper(), cell_style),
                ])
            t_threats_overview = Table(threat_rows, colWidths=[5.5*cm, 2.5*cm, 2.0*cm, 1.5*cm, 1.2*cm, 4.3*cm])
            t_threats_overview.setStyle(_hdr)

        # ── 2. Table IOCs ─────────────────────────────────────────────────────
        ioc_rows = [[
            Paragraph("Type", cell_header_style),
            Paragraph("Valeur", cell_header_style),
            Paragraph("Source", cell_header_style),
            Paragraph("Sévérité", cell_header_style),
            Paragraph("STIX ID", cell_header_style)
        ]]
        
        for ind in indicators_sorted:
            itype, val = parse_pattern(ind.get("pattern", ""))
            src = ", ".join(ind.get("x_ioc_sources", ["MISP"]))
            prio = ind.get("x_ioc_priority", "LOW").upper()
            prio_color = "#10b981" if prio == "LOW" else "#eab308" if prio == "MEDIUM" else "#f97316" if prio == "HIGH" else "#ef4444"
            sid = ind.get("id", "").split('--')[-1][:8] + "..."
            
            ioc_rows.append([
                Paragraph(itype, cell_style),
                Paragraph(val, cell_style),
                Paragraph(src, cell_style),
                Paragraph(f"<font color='{prio_color}'><b>{prio}</b></font>", cell_style),
                Paragraph(sid, cell_style)
            ])
            
        if len(ioc_rows) == 1:
            ioc_rows.append([Paragraph("-", cell_style), Paragraph("Aucun indicateur disponible", cell_style), Paragraph("-", cell_style), Paragraph("-", cell_style), Paragraph("-", cell_style)])

        t_ioc = Table(ioc_rows, colWidths=[2.5 * cm, 6.0 * cm, 3.0 * cm, 2.5 * cm, 3.0 * cm])
        t_ioc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))

        # ── 3. Table Enrichissement ──────────────────────────────────────────
        enrich_rows = [[
            Paragraph("IOC", cell_header_style),
            Paragraph("Géolocalisation / Contexte", cell_header_style),
            Paragraph("Score / Réputation", cell_header_style),
            Paragraph("Detections VT", cell_header_style),
            Paragraph("MISP Event", cell_header_style)
        ]]
        
        for ind in indicators_sorted:
            itype, val = parse_pattern(ind.get("pattern", ""))
            enrich = None
            misp_event = None
            for ev in corr_events:
                for ioc in ev.get("iocs", []):
                    if ioc.get("value") == val:
                        enrich = ioc.get("enrichment", {})
                        misp_event = ev.get("group_id")
                        break
                if enrich is not None:
                    break
                    
            if enrich is not None:
                # Géolocalisation
                geo_parts = []
                cc = enrich.get("countryCode") or enrich.get("country_code") or enrich.get("urlscan_country")
                cname = enrich.get("country")
                if cc:
                    geo_parts.append(cc)
                if cname:
                    geo_parts.append(cname)
                isp = enrich.get("isp") or enrich.get("as_owner")
                if isp:
                    geo_parts.append(f"({isp})")
                geoloc = " — ".join(geo_parts) if geo_parts else "—"
                
                # Réputation / Score
                score = "—"
                if "abuseConfidenceScore" in enrich:
                    score = f"AbuseIPDB: {enrich['abuseConfidenceScore']}%"
                elif enrich.get("risk_flag"):
                    flag = enrich["risk_flag"].lower()
                    s_val = 90 if flag == "high" else 60 if flag == "medium" else 15
                    score = f"URLScan: {s_val}/100"
                elif enrich.get("vt_reputation") is not None:
                    score = f"VT Rep: {enrich['vt_reputation']}"
                    
                # VT Detections
                det = "—"
                if "vt_malicious_count" in enrich:
                    det = f"{enrich.get('vt_malicious_count', 0)} / {enrich.get('vt_total_engines', 0)}"
                    
                mevent = f"#{misp_event}" if misp_event else "—"
            else:
                geoloc = "—"
                score = "—"
                det = "—"
                mevent = "—"
                
            enrich_rows.append([
                Paragraph(val, cell_style),
                Paragraph(geoloc, cell_style),
                Paragraph(score, cell_style),
                Paragraph(det, cell_style),
                Paragraph(mevent, cell_style)
            ])
            
        if len(enrich_rows) == 1:
            enrich_rows.append([Paragraph("-", cell_style), Paragraph("Pas d'enrichissement disponible", cell_style), Paragraph("-", cell_style), Paragraph("-", cell_style), Paragraph("-", cell_style)])

        t_enrich = Table(enrich_rows, colWidths=[4.5 * cm, 4.5 * cm, 2.5 * cm, 2.5 * cm, 3.0 * cm])
        t_enrich.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))

        # ── 4. Table MITRE ATT&CK ─────────────────────────────────────────────
        observed_techniques = set()
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                name = obj.get("name")
                if name:
                    observed_techniques.add(name)
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        observed_techniques.add(ref.get("external_id"))

        checklist_techniques = [
            ("T1566.001", "Initial Access", "Spearphishing Attachment"),
            ("T1071.001", "Command &amp; Control", "Web Protocols (HTTP/S C2)"),
            ("T1539", "Credential Access", "Steal Web Session Cookie"),
            ("T1486", "Impact", "Data Encrypted for Impact"),
            ("T1027", "Defense Evasion", "Obfuscated Files or Information")
        ]

        checklist_ids = {t[0] for t in checklist_techniques}
        for tid in sorted(observed_techniques):
            base_tid = tid.split('.')[0]
            if tid not in checklist_ids and base_tid not in checklist_ids:
                tinfo = MITRE_NAMES.get(tid) or MITRE_NAMES.get(base_tid)
                if tinfo:
                    tactic, tname = tinfo
                else:
                    tactic, tname = "Other", tid
                checklist_techniques.append((tid, tactic, tname))

        mitre_rows = [[
            Paragraph("ID Technique", cell_header_style),
            Paragraph("Tactique", cell_header_style),
            Paragraph("Technique", cell_header_style),
            Paragraph("Observé", cell_header_style)
        ]]
        
        for tid, tactic, tname in checklist_techniques:
            observed = "✗"
            if tid in observed_techniques or tid.split('.')[0] in observed_techniques:
                observed = "✓"
            
            obs_color = "#10b981" if observed == "✓" else "#ef4444"
            
            mitre_rows.append([
                Paragraph(tid, cell_style),
                Paragraph(tactic, cell_style),
                Paragraph(tname, cell_style),
                Paragraph(f"<font color='{obs_color}'><b>{observed}</b></font>", cell_style)
            ])
            
        t_mitre = Table(mitre_rows, colWidths=[3.0 * cm, 5.0 * cm, 6.0 * cm, 3.0 * cm])
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))

        # ── 5. Structure du Bundle STIX ───────────────────────────────────────
        preview_objects = []
        identities = [o for o in objects if o.get("type") == "identity"]
        if identities:
            preview_objects.append({
                "type": "identity",
                "id": identities[0].get("id"),
                "name": identities[0].get("name")
            })
        if indicators_sorted:
            preview_objects.append({
                "type": "indicator",
                "id": indicators_sorted[0].get("id"),
                "pattern": indicators_sorted[0].get("pattern"),
                "valid_from": indicators_sorted[0].get("valid_from")
            })
        if threats_sorted:
            preview_objects.append({
                "type": threats_sorted[0].get("type"),
                "id": threats_sorted[0].get("id"),
                "name": threats_sorted[0].get("name"),
                "x_soc_priority": threats_sorted[0].get("x_soc_priority")
            })
        relationships = [o for o in objects if o.get("type") == "relationship"]
        if relationships:
            preview_objects.append({
                "type": "relationship",
                "id": relationships[0].get("id"),
                "source_ref": relationships[0].get("source_ref"),
                "target_ref": relationships[0].get("target_ref"),
                "relationship_type": relationships[0].get("relationship_type")
            })
            
        stix_bundle_preview = {
            "type": "bundle",
            "id": bundle.get("id", "bundle--dynamic-id"),
            "objects": preview_objects
        }
        stix_json = json.dumps(stix_bundle_preview, indent=2)

        p_stix_desc = Paragraph(
            f"Le bundle STIX est automatiquement injecté dans MISP via l'API REST (POST /events). Chaque indicateur est corrélé aux événements existants et taggé {tlp_text} / PAP:RED selon la politique SOC.",
            styles['Normal']
        )
        p_stix_code = Paragraph(
            stix_json.replace(" ", "&nbsp;").replace("\n", "<br/>"),
            code_style
        )

        # ── 6. Recommandations SOC ────────────────────────────────────────────
        recommandations = []
        has_ips = any(parse_pattern(ind.get("pattern",""))[0] in ["IP", "Domain", "URL"] for ind in indicators_sorted)
        has_hashes = any(parse_pattern(ind.get("pattern",""))[0] == "Hash" for ind in indicators_sorted)
        has_phish = any(t.get("type") == "campaign" for t in threats_sorted)
        has_vuln = any(t.get("type") == "vulnerability" for t in threats_sorted)
        
        if has_ips:
            recommandations.append(("R1", "Bloquer les IPs / domaines listés en section 2 sur le firewall périmétrique et proxy web.", "IMMÉDIATE", "SOC L1"))
        else:
            recommandations.append(("R1", "Surveiller les connexions réseau inhabituelles vers les IOCs suspectés.", "HAUTE", "SOC L1"))
            
        if has_hashes:
            recommandations.append(("R2", "Soumettre les hashes de fichiers à l'EDR pour hunting rétrospectif (30 jours).", "HAUTE", "SOC L2"))
        else:
            recommandations.append(("R2", "Vérifier l'intégrité des hôtes et systèmes d'écriture suspectes.", "MOYENNE", "SOC L2"))
            
        if has_phish:
            recommandations.append(("R3", "Notifier les utilisateurs ciblés par la campagne de phishing et réinitialiser les identifiants compromis.", "HAUTE", "CISO"))
        elif has_vuln:
            recommandations.append(("R3", "Appliquer d'urgence les correctifs de sécurité prioritaires sur les systèmes affectés.", "HAUTE", "Admin Sys"))
        else:
            recommandations.append(("R3", "Informer les équipes opérationnelles et sensibiliser à la menace.", "MOYENNE", "SOC Manager"))
            
        recommandations.append(("R4", "Déployer et activer les règles de détection (Sigma/Yara) correspondantes dans le SIEM/EDR.", "MOYENNE", "SOC L2"))
        recommandations.append(("R5", "Exporter le bundle STIX 2.1 vers les partenaires ISAC et plateformes de partage de confiance.", "BASSE", "CTI Lead"))

        reco_rows = [[
            Paragraph("#", cell_header_style),
            Paragraph("Action", cell_header_style),
            Paragraph("Priorité", cell_header_style),
            Paragraph("Responsable", cell_header_style)
        ]]
        
        for rid, action, prio, resp in recommandations:
            prio_color = "#ef4444" if prio == "IMMÉDIATE" else "#f97316" if prio == "HAUTE" else "#eab308" if prio == "MOYENNE" else "#10b981"
            
            reco_rows.append([
                Paragraph(rid, cell_bold_style),
                Paragraph(action, cell_style),
                Paragraph(f"<font color='{prio_color}'><b>{prio}</b></font>", cell_style),
                Paragraph(resp, cell_style)
            ])
            
        t_reco = Table(reco_rows, colWidths=[1.5 * cm, 10.0 * cm, 2.5 * cm, 3.0 * cm])
        t_reco.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9fafb")]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))

        # ── Construction du Document PDF ──────────────────────────────────────
        now_utc = datetime.now(timezone.utc)
        months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
        date_str = f"{now_utc.day} {months[now_utc.month - 1]} {now_utc.year} — {now_utc.strftime('%H:%M')}Z"
        ref_id = f"CTI-BULL-{now_utc.year}-001"

        date_tag = now_utc.strftime("%Y%m%d_%H%M%S")
        if not output_path:
            if threat_filter_id and threats_sorted:
                safe_name = re.sub(r"[^\w\-]", "_", threats_sorted[0].get("name", "threat"))[:35]
                output_path = os.path.join(self.reports_dir, f"bulletin_{safe_name}_{date_tag}.pdf")
            else:
                output_path = os.path.join(self.reports_dir, f"cti_bulletin_{date_tag}.pdf")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=2.0 * cm,
            rightMargin=2.0 * cm,
            topMargin=4.2 * cm,
            bottomMargin=2.6 * cm
        )

        def draw_header_footer(canvas, doc):
            canvas.saveState()
            
            # Header line
            canvas.setStrokeColor(colors.HexColor("#17365d"))
            canvas.setLineWidth(1)
            canvas.line(2.0 * cm, A4[1] - 3.6 * cm, A4[0] - 2.0 * cm, A4[1] - 3.6 * cm)
            
            # Header Text Left
            canvas.setFont('Helvetica-Bold', 10)
            canvas.setFillColor(colors.HexColor("#17365d"))
            canvas.drawString(2.0 * cm, A4[1] - 1.2 * cm, "BLUESEC SOC · CYBER THREAT INTELLIGENCE")
            
            # Header Text Right: Confidentiality
            canvas.setFont('Helvetica-Bold', 9)
            canvas.setFillColor(tlp_color)
            canvas.drawRightString(A4[0] - 2.0 * cm, A4[1] - 1.2 * cm, classif_text)
            
            # Header Main Title
            canvas.setFont('Helvetica-Bold', 16)
            canvas.setFillColor(colors.HexColor("#17365d"))
            canvas.drawString(2.0 * cm, A4[1] - 2.2 * cm, "Security Bulletin")
            
            # Header Subtitle
            canvas.setFont('Helvetica-Oblique', 9)
            canvas.setFillColor(colors.HexColor("#555555"))
            canvas.drawString(2.0 * cm, A4[1] - 2.7 * cm, "Rapport d'analyse CTI — Export STIX 2.1")
            
            # Header Meta Right
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor("#555555"))
            canvas.drawRightString(A4[0] - 2.0 * cm, A4[1] - 2.2 * cm, date_str)
            canvas.drawRightString(A4[0] - 2.0 * cm, A4[1] - 2.6 * cm, f"Réf : {ref_id}")
            canvas.drawRightString(A4[0] - 2.0 * cm, A4[1] - 3.0 * cm, "STIX 2.1 Compatible")
            
            # Footer Line
            canvas.setStrokeColor(colors.HexColor("#17365d"))
            canvas.setLineWidth(1)
            canvas.line(2.0 * cm, 2.0 * cm, A4[0] - 2.0 * cm, 2.0 * cm)
            
            # Footer Text Left
            canvas.setFont('Helvetica', 7.5)
            canvas.setFillColor(colors.HexColor("#666666"))
            canvas.drawString(2.0 * cm, 1.4 * cm, "Généré automatiquement par le CTI Pipeline BlueSec | MISP v2.4 · VirusTotal · URLScan.io · GeoIP")
            
            # Footer Text Right
            canvas.drawRightString(A4[0] - 2.0 * cm, 1.4 * cm, f"Classification : {tlp_text} | Page {doc.page}")
            
            canvas.restoreState()

        # Construction de l'arborescence des flowables
        story = []
        n = 1  # numérotation des sections

        # Section 1 — Résumé Exécutif
        story.append(Paragraph(f"{n}. Résumé Exécutif", title_style)); n += 1
        story.append(t_summary)
        story.append(Spacer(1, 0.4 * cm))

        # Section 2 — Vue d'ensemble des menaces (mode consolidé uniquement)
        if t_threats_overview is not None:
            story.append(Paragraph(f"{n}. Vue d'ensemble des Menaces", title_style)); n += 1
            story.append(t_threats_overview)
            story.append(Spacer(1, 0.4 * cm))

        # Section IOCs
        story.append(Paragraph(f"{n}. Indicateurs de Compromission (IOCs)", title_style)); n += 1
        story.append(t_ioc)
        story.append(Spacer(1, 0.4 * cm))

        # Section Enrichissement
        story.append(Paragraph(f"{n}. Enrichissement &amp; Corrélation", title_style)); n += 1
        story.append(t_enrich)
        story.append(Spacer(1, 0.4 * cm))

        # Section MITRE
        story.append(Paragraph(f"{n}. Tactiques &amp; Techniques MITRE ATT&amp;CK", title_style)); n += 1
        story.append(t_mitre)

        story.append(PageBreak())

        # Section STIX
        story.append(Paragraph(f"{n}. Export STIX 2.1 — Structure du Bundle", title_style)); n += 1
        story.append(p_stix_desc)
        story.append(Spacer(1, 0.2 * cm))
        story.append(p_stix_code)
        story.append(Spacer(1, 0.4 * cm))

        # Section Recommandations
        story.append(Paragraph(f"{n}. Recommandations SOC", title_style))
        story.append(t_reco)

        try:
            doc.build(story, onFirstPage=draw_header_footer, onLaterPages=draw_header_footer)
            print(f"[STIXReporter] Bulletin PDF généré avec succès : {output_path}")
            return output_path
        except Exception as e:
            print(f"[STIXReporter] Erreur lors de la construction du PDF : {e}")
            return None


    def generate_pdf_per_threat(self) -> list:
        """Génère un bulletin PDF distinct pour chaque menace du bundle STIX."""
        if not os.path.exists(self.input_file):
            print(f"[STIXReporter] Fichier STIX introuvable: {self.input_file}")
            return []

        try:
            with open(self.input_file, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except Exception as e:
            print(f"[STIXReporter] Erreur de décodage STIX: {e}")
            return []

        objects = bundle.get("objects", [])
        main_types = {"malware", "vulnerability", "campaign", "infrastructure"}
        threats = [o for o in objects if o.get("type") in main_types]

        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threats_sorted = sorted(
            threats,
            key=lambda x: (priority_order.get(x.get("x_soc_priority", "LOW").upper(), 4), -x.get("x_soc_risk", 0.0))
        )

        if not threats_sorted:
            print("[STIXReporter] Aucune menace trouvée dans le bundle STIX.")
            return []

        print(f"[STIXReporter] {len(threats_sorted)} menace(s) trouvée(s) — génération des bulletins...")
        generated = []

        for threat in threats_sorted:
            tid   = threat.get("id")
            tname = threat.get("name", "unknown")
            tprio = threat.get("x_soc_priority", "LOW")
            print(f"  -> Bulletin : {tname} [{tprio}]")
            path = self.generate_pdf(threat_filter_id=tid)
            if path:
                generated.append(path)

        print(f"\n[STIXReporter] {len(generated)} bulletin(s) générés dans : {self.reports_dir}")
        return generated


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Génère un bulletin PDF consolidé à partir d'un bundle STIX 2.1")
    parser.add_argument("-i", "--input", help="Fichier STIX bundle (input)", default=OUTPUT_FILE)
    parser.add_argument("--per-threat", action="store_true",
                        help="Génère un bulletin PDF séparé par menace (au lieu du rapport unique)")
    args = parser.parse_args()

    reporter = STIXReporter(input_file=args.input)
    if args.per_threat:
        reporter.generate_pdf_per_threat()
    else:
        reporter.generate_pdf()