import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import os
import json
import uuid
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

def get_stix_id(type_name):
    return f"{type_name}--{uuid.uuid4()}"

def extract_events_from_stix(stix_file_path):
    with open(stix_file_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
        
    objects_by_id = {obj["id"]: obj for obj in bundle.get("objects", [])}
    reports = [obj for obj in bundle.get("objects", []) if obj.get("type") == "report"]
    
    events = []
    for rep in reports:
        event = {}
        main_obj = None
        mitre_techs = []
        iocs = []
        
        for ref in rep.get("object_refs", []):
            obj = objects_by_id.get(ref)
            if not obj: continue
            
            t = obj.get("type")
            if t in ["malware", "campaign", "vulnerability", "infrastructure"]:
                main_obj = obj
            elif t == "attack-pattern":
                mitre_techs.append(obj.get("name"))
            elif t == "indicator":
                name_parts = obj.get("name", "").split(" - ", 1)
                i_type = name_parts[0] if len(name_parts) > 1 else "indicator"
                val = name_parts[1] if len(name_parts) > 1 else obj.get("name", "")
                
                desc = obj.get("description", "")
                geo = "N/A"
                vt_str = "-"
                abuse_str = "-"
                urlscan_str = "-"
                for line in desc.split("\n"):
                    if line.startswith("Country"): geo = line.split(":", 1)[1].strip()
                    if line.startswith("VirusTotal"): vt_str = line.split(":", 1)[1].strip()
                    if line.startswith("AbuseIPDB"): abuse_str = line.split(":", 1)[1].strip()
                    if line.startswith("URLScan"): urlscan_str = line.split(":", 1)[1].strip()
                
                iocs.append({
                    "type": i_type,
                    "value": val,
                    "sources": obj.get("x_ioc_sources", []),
                    "risk_level": obj.get("x_ioc_risk_level", "low"),
                    "enrichment": {
                        "country": geo,
                        "vt_str": vt_str,
                        "abuse_str": abuse_str,
                        "urlscan_str": urlscan_str
                    },
                    "stix_id": obj.get("id")
                })
                
        if main_obj:
            event["group_id"] = main_obj.get("x_soc_group_id", "EVENT")
            event["event_name"] = main_obj.get("name", "Unknown")
            event["priority_score"] = main_obj.get("x_soc_priority", "LOW")
            event["threat_type"] = main_obj.get("type", "Unknown")
            event["confidence_score"] = main_obj.get("confidence", 0)
            event["attack_type"] = "Unknown"
            event["first_seen"] = main_obj.get("first_seen", "")
            event["last_seen"] = main_obj.get("last_seen", "")
            event["soc_action"] = main_obj.get("x_soc_action", "monitor")
        else:
            event["group_id"] = rep.get("id")
            event["event_name"] = rep.get("name", "Unknown")
            event["priority_score"] = "LOW"
            
        event["mitre_techniques"] = mitre_techs
        event["iocs"] = iocs
        events.append(event)
        
    # Trier les événements par priorité (CRITICAL -> HIGH -> MEDIUM -> LOW)
    priority_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    events.sort(key=lambda x: priority_map.get(x.get("priority_score", "LOW"), 0), reverse=True)
    return events


class CTIBulletinGenerator:
    def __init__(self, output_dir="reports/cti_bulletins"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='TitleStyle', fontSize=18, leading=22, spaceAfter=10, textColor=colors.HexColor("#17365d"), fontName="Helvetica-Bold"))
        self.styles.add(ParagraphStyle(name='SubtitleStyle', fontSize=12, leading=15, spaceAfter=5, textColor=colors.HexColor("#333333"), fontName="Helvetica-Bold"))
        self.styles.add(ParagraphStyle(name='HeaderRight', fontSize=10, alignment=2, textColor=colors.HexColor("#666666")))
        self.styles.add(ParagraphStyle(name='SectionTitle', fontSize=14, leading=18, spaceBefore=15, spaceAfter=10, textColor=colors.HexColor("#17365d"), fontName="Helvetica-Bold", backColor=colors.HexColor("#f2f2f2"), borderPadding=(5, 5, 5, 5)))
        self.styles.add(ParagraphStyle(name='NormalText', fontSize=10, leading=14, spaceAfter=5, textColor=colors.black))

    def header_footer(self, canvas, doc):
        canvas.saveState()
        
        # Header Left: BlueSec
        text_x = doc.leftMargin
        canvas.setFont('Helvetica-Bold', 12)
        canvas.setFillColor(colors.HexColor("#17365d"))
        canvas.drawString(text_x, A4[1] - 40, "BLUESEC SOC · CYBER THREAT INTELLIGENCE")
        
        # Header Right: Confidentiel
        canvas.setFont('Helvetica-Oblique', 9)
        canvas.setFillColor(colors.HexColor("#d32f2f"))
        canvas.drawString(A4[0] - doc.rightMargin - 150, A4[1] - 40, "TLP:RED - Confidentiel")
        
        # Footer
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawString(doc.leftMargin, 30, f"Généré par le CTI Pipeline BlueSec · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 30, f"Page {doc.page}")
        
        # Lines
        canvas.setStrokeColor(colors.HexColor("#17365d"))
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin, A4[1] - 60, A4[0] - doc.rightMargin, A4[1] - 60)
        canvas.line(doc.leftMargin, 45, A4[0] - doc.rightMargin, 45)
        
        canvas.restoreState()

    def generate_consolidated_pdf(self, stix_file_path, events):
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f"Bulletin_CTI_STIX_{date_str}.pdf")
        
        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2.5*cm, bottomMargin=2.5*cm)
        story = []

        # ----------------------------------------------------
        # PAGE DE GARDE
        # ----------------------------------------------------
        story.append(Spacer(1, 2.5*cm))
        logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bluesec-logo.png"))
        if os.path.exists(logo_path):
            img = Image(logo_path, width=9*cm, height=3.5*cm, kind='proportional')
            img.hAlign = 'CENTER'
            story.append(img)
            story.append(Spacer(1, 2*cm))
            
        cover_title_style = ParagraphStyle(name='CoverTitle', fontSize=28, leading=34, alignment=1, spaceAfter=20, textColor=colors.HexColor("#17365d"), fontName="Helvetica-Bold")
        cover_subtitle_style = ParagraphStyle(name='CoverSubtitle', fontSize=16, leading=20, alignment=1, spaceAfter=10, textColor=colors.HexColor("#333333"))
        cover_red_style = ParagraphStyle(name='CoverRed', fontSize=16, leading=20, alignment=1, spaceAfter=10, textColor=colors.HexColor("#d32f2f"), fontName="Helvetica-Bold")

        story.append(Spacer(1, 4*cm))
        story.append(Paragraph("BULLETIN DE SÉCURITÉ CTI", cover_title_style))
        story.append(Paragraph("Intelligence sur les menaces et indicateurs de compromission", cover_subtitle_style))
        story.append(Spacer(1, 1*cm))
        story.append(Paragraph(f"Date de génération : {datetime.now().strftime('%d %B %Y — %H:%M UTC')}", cover_subtitle_style))
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("TLP:RED - Document Confidentiel", cover_red_style))
        
        story.append(PageBreak())

        # ----------------------------------------------------
        # SOMMAIRE
        # ----------------------------------------------------
        story.append(Paragraph("Sommaire des Menaces Détectées", self.styles['TitleStyle']))
        story.append(Paragraph(f"Généré depuis l'export STIX : {os.path.basename(stix_file_path)}", self.styles['SubtitleStyle']))
        story.append(Spacer(1, 0.5*cm))
        summary_data = [["Nom de l'Événement", "Priorité", "IOCs"]]
        for ev in events:
            priority = ev.get('priority_score', 'LOW')
            color = "#d32f2f" if priority == "CRITICAL" else ("#f57c00" if priority == "HIGH" else "#17365d")
            summary_data.append([
                Paragraph(ev.get('event_name', 'Unknown')[:60], self.styles['NormalText']),
                Paragraph(f"<font color='{color}'><b>{priority}</b></font>", self.styles['NormalText']),
                str(len(ev.get('iocs', [])))
            ])
            
        t_sum = Table(summary_data, colWidths=[9*cm, 3.5*cm, 3.5*cm])
        t_sum.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_sum)
        story.append(PageBreak())

        # ----------------------------------------------------
        # DETAILS PAR ENREGISTREMENT
        # ----------------------------------------------------
        for i, event in enumerate(events):
            story.append(Paragraph(f"Dossier {i+1} : {event.get('event_name', 'Unknown')}", self.styles['TitleStyle']))
            
            # Sévérité & Contexte
            severity_color = colors.HexColor("#d32f2f") if event.get("priority_score") == "CRITICAL" else colors.HexColor("#f57c00")
            
            info_data = [
                ["Sévérité", Paragraph(f"<font color='{severity_color.hexval()}'><b>{event.get('priority_score', 'UNKNOWN')}</b></font>", self.styles['NormalText'])],
                ["Type de menace", event.get("threat_type", "Unknown").replace('_', ' ').title()],
                ["Période observée", f"{event.get('first_seen', '')[:10]} → {event.get('last_seen', '')[:10]}"],
                ["Techniques MITRE", Paragraph(", ".join(event.get("mitre_techniques", []))[:80], self.styles['NormalText'])]
            ]
            
            t_info = Table(info_data, colWidths=[4*cm, 12*cm])
            t_info.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f2f2f2")),
                ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#17365d")),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(t_info)
            story.append(Spacer(1, 0.5*cm))

            # Indicateurs de compromission
            story.append(Paragraph("Indicateurs de Compromission (IOCs) associés", self.styles['SubtitleStyle']))
            ioc_table_data = [["Type", "Valeur de l'IOC", "Géolocalisation", "Détections (VT/Abuse)"]]
            
            for ioc in event.get("iocs", [])[:25]: # Limite à 25 IOCs pour la lisibilité
                val = ioc.get("value", "")
                if len(val) > 40: val = val[:37] + "..."
                
                e = ioc.get("enrichment", {})
                geo = e.get("country", "N/A")
                if len(geo) > 15: geo = geo[:12] + "..."
                
                vt = e.get("vt_str", "-")
                abuse = e.get("abuse_str", "-")
                if vt != "-" and vt != "": det = f"VT: {vt}"
                elif abuse != "-" and abuse != "": det = f"Abuse: {abuse}"
                else: det = "-"
                
                if len(det) > 25: det = det[:22] + "..."
                
                ioc_table_data.append([ioc.get("type", "").upper(), val, geo, det])
                
            if not event.get("iocs"):
                ioc_table_data.append(["-", "Aucun IOC répertorié", "-", "-"])
                
            t_iocs = Table(ioc_table_data, colWidths=[2.5*cm, 7*cm, 3.5*cm, 3*cm])
            t_iocs.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t_iocs)
            
            # Recommandations
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph("Action SOC Recommandée", self.styles['SubtitleStyle']))
            action = event.get('soc_action', 'monitor')
            if action == 'escalate': txt = "<b>ESCALADE IMMÉDIATE</b> : Bloquer les IOCs actifs sur les pare-feux et EDR. Lancer une réponse à incident."
            elif action == 'investigate': txt = "<b>INVESTIGATION REQUISE</b> : Analyser les logs pour vérifier s'il y a eu des requêtes vers ces IOCs."
            else: txt = "<b>MONITORING</b> : Ajouter ces IOCs aux listes de surveillance passives."
            story.append(Paragraph(txt, self.styles['NormalText']))
            
            story.append(Spacer(1, 1.5*cm))

        doc.build(story, onFirstPage=self.header_footer, onLaterPages=self.header_footer)
        return filename

def main(input_file=None):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_corr_dir = os.path.join(base_dir, "global_output", "output_correlation")
    output_dir = os.path.join(base_dir, "reports", "cti_bulletins")
    
    if not input_file:
        files = [f for f in os.listdir(out_corr_dir) if f.startswith("stix_export_") and f.endswith(".json")]
        if not files:
            print("Aucun export STIX trouvé dans output_correlation.")
            return
        input_file = max([os.path.join(out_corr_dir, f) for f in files], key=os.path.getmtime)
        
    print(f"Lecture du fichier STIX : {input_file}")
    
    try:
        events = extract_events_from_stix(input_file)
        print(f"{len(events)} enregistrements extraits du bundle STIX.")
    except Exception as e:
        print(f"Erreur lors de l'extraction STIX: {e}")
        return
        
    if not events:
        print("Aucun événement à générer.")
        return
        
    generator = CTIBulletinGenerator(output_dir=output_dir)
    print("Génération du Bulletin de Sécurité consolidé...")
    
    try:
        pdf_path = generator.generate_consolidated_pdf(input_file, events)
        print(f"\n[SUCCÈS] Bulletin généré : {pdf_path}")
    except Exception as e:
        print(f"Erreur lors de la génération PDF : {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Générer un Bulletin CTI depuis un export STIX JSON")
    parser.add_argument("-i", "--input", help="Fichier STIX JSON (ex: stix_export_xxx.json)")
    args = parser.parse_args()
    
    main(input_file=args.input)
