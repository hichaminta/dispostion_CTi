import os
import json
import uuid
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak

def get_stix_id(type_name):
    return f"{type_name}--{uuid.uuid4()}"

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
        self.styles.add(ParagraphStyle(name='CodeBlock', fontSize=8, leading=10, fontName="Courier", spaceAfter=10, textColor=colors.HexColor("#111111"), backColor=colors.HexColor("#f5f5f5"), borderPadding=(10, 10, 10, 10)))

    def header_footer(self, canvas, doc):
        canvas.saveState()
        
        # Header Left: BlueSec
        canvas.setFont('Helvetica-Bold', 12)
        canvas.setFillColor(colors.HexColor("#17365d"))
        canvas.drawString(doc.leftMargin, A4[1] - 40, "BLUESEC SOC · CYBER THREAT INTELLIGENCE")
        
        # Header Right: Confidentiel
        canvas.setFont('Helvetica-Oblique', 9)
        canvas.setFillColor(colors.HexColor("#d32f2f"))
        canvas.drawString(A4[0] - doc.rightMargin - 150, A4[1] - 40, "TLP:RED - Confidentiel")
        
        # Footer
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawString(doc.leftMargin, 30, f"Généré automatiquement par le CTI Pipeline BlueSec · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 30, f"Page {doc.page}")
        
        # Lines
        canvas.setStrokeColor(colors.HexColor("#17365d"))
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin, A4[1] - 45, A4[0] - doc.rightMargin, A4[1] - 45)
        canvas.line(doc.leftMargin, 45, A4[0] - doc.rightMargin, 45)
        
        canvas.restoreState()

    def generate_pdf(self, event):
        ref_id = f"CTI-BULL-{datetime.now().strftime('%Y')}-{str(uuid.uuid4())[:4].upper()}"
        filename = os.path.join(self.output_dir, f"{ref_id}_{event.get('group_id', 'EVENT')}.pdf")
        
        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2.5*cm, bottomMargin=2.5*cm)
        story = []

        # ----------------------------------------------------
        # HEADER INFO
        # ----------------------------------------------------
        story.append(Paragraph("Security Bulletin", self.styles['TitleStyle']))
        story.append(Paragraph("Rapport d'analyse CTI — Export STIX 2.1", self.styles['SubtitleStyle']))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%d %B %Y — %H:%MZ')}<br/>Réf : {ref_id}<br/>STIX 2.1 Compatible", self.styles['HeaderRight']))
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 1. Résumé Exécutif
        # ----------------------------------------------------
        story.append(Paragraph("1. Résumé Exécutif", self.styles['SectionTitle']))
        
        severity_color = colors.HexColor("#d32f2f") if event.get("priority_score") == "CRITICAL" else colors.HexColor("#f57c00")
        
        summary_data = [
            ["Campagne / Événement", Paragraph(event.get("event_name", "Unknown"), self.styles['NormalText'])],
            ["Sévérité", Paragraph(f"<font color='{severity_color.hexval()}'><b>{event.get('priority_score', 'UNKNOWN')}</b></font>", self.styles['NormalText'])],
            ["Type de menace", event.get("threat_type", "Unknown").replace('_', ' ').title()],
            ["Confidence", f"{event.get('confidence_score', 0)} %"],
            ["Acteur suspecté", ", ".join(event.get("threat_actors", [])) or "Inconnu"],
            ["Vecteur", event.get("attack_type", "Inconnu")],
            ["Période observée", f"{event.get('first_seen', '')[:10]} → {event.get('last_seen', '')[:10]}"],
            ["Impact SOC", event.get("soc_action", "monitor").replace('_', ' ').title()]
        ]
        
        t_summary = Table(summary_data, colWidths=[5*cm, 11*cm])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f2f2f2")),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#17365d")),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 2. Indicateurs de Compromission (IOCs)
        # ----------------------------------------------------
        story.append(Paragraph("2. Indicateurs de Compromission (IOCs)", self.styles['SectionTitle']))
        
        ioc_table_data = [["Type", "Valeur", "Source", "Sévérité", "STIX ID"]]
        
        # Max 15 IOCs in summary to avoid huge tables
        stix_mapping = {}
        for ioc in event.get("iocs", [])[:15]:
            i_type = ioc.get("type", "unknown").upper()
            val = ioc.get("value", "")
            if len(val) > 30: val = val[:27] + "..."
            
            stix_id = get_stix_id(ioc.get("type", "indicator"))
            stix_mapping[ioc.get("value")] = stix_id
            
            src = ", ".join(ioc.get("sources", []))
            if len(src) > 15: src = src[:12] + "..."
            
            lvl = ioc.get("risk_level", "low").upper()
            
            ioc_table_data.append([i_type, val, src, lvl, stix_id.split('--')[1][:8] + "..."])
            
        if not event.get("iocs"):
            ioc_table_data.append(["-", "Aucun IOC", "-", "-", "-"])

        t_iocs = Table(ioc_table_data, colWidths=[2.5*cm, 5.5*cm, 3*cm, 2.5*cm, 2.5*cm])
        t_iocs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'), # values aligned left
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_iocs)
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 3. Enrichissement & Corrélation
        # ----------------------------------------------------
        story.append(Paragraph("3. Enrichissement & Corrélation", self.styles['SectionTitle']))
        
        enrich_data = [["IOC", "Géolocalisation / Contexte", "Score Externe", "Détections"]]
        
        for ioc in event.get("iocs", [])[:10]:
            val = ioc.get("value", "")
            if len(val) > 25: val = val[:22] + "..."
            
            e = ioc.get("enrichment", {})
            geo = e.get("country", e.get("countryCode", "N/A"))
            
            score = "-"
            if "abuseConfidenceScore" in e: score = f"AbuseIPDB: {e['abuseConfidenceScore']}"
            elif "urlscan_score" in e: score = f"URLScan: {e['urlscan_score']}"
            
            det = f"VT: {e.get('vt_malicious_count', 0)}/{e.get('vt_total_engines', 0)}" if 'vt_malicious_count' in e else "-"
            
            enrich_data.append([val, geo, score, det])

        if len(enrich_data) == 1:
            enrich_data.append(["-", "Pas d'enrichissement", "-", "-"])

        t_enrich = Table(enrich_data, colWidths=[5*cm, 5*cm, 3.5*cm, 2.5*cm])
        t_enrich.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ALIGN', (0,1), (1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_enrich)
        
        # ----------------------------------------------------
        # Page Break before STIX if needed, or just let it flow
        # ----------------------------------------------------
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 4. Tactiques & Techniques MITRE ATT&CK
        # ----------------------------------------------------
        story.append(Paragraph("4. Tactiques & Techniques MITRE ATT&CK", self.styles['SectionTitle']))
        
        mitre_data = [["ID Technique", "Description / Tactic", "Observé"]]
        for t in event.get("mitre_techniques", []):
            mitre_data.append([t, "Lié au profil comportemental", "✓"])
            
        if len(mitre_data) == 1:
            mitre_data.append(["N/A", "Aucune technique spécifiée", "✗"])
            
        t_mitre = Table(mitre_data, colWidths=[4*cm, 10*cm, 2*cm])
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_mitre)
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 5. Export STIX 2.1 — Structure du Bundle
        # ----------------------------------------------------
        story.append(Paragraph("5. Export STIX 2.1 — Structure du Bundle", self.styles['SectionTitle']))
        
        stix_bundle = {
            "type": "bundle",
            "id": get_stix_id("bundle"),
            "objects": [
                {
                    "type": "report",
                    "id": get_stix_id("report"),
                    "name": event.get("event_name"),
                    "published": datetime.now().isoformat() + "Z",
                    "object_refs": list(stix_mapping.values())[:3] # show first 3
                }
            ]
        }
        stix_json = json.dumps(stix_bundle, indent=2)
        story.append(Paragraph(stix_json.replace(" ", "&nbsp;").replace("\n", "<br/>"), self.styles['CodeBlock']))
        
        story.append(Paragraph("Le bundle STIX est prêt à être injecté dans MISP via l'API REST. Chaque indicateur est corrélé aux événements existants et taggé selon la politique SOC.", self.styles['NormalText']))
        story.append(Spacer(1, 0.5*cm))

        # ----------------------------------------------------
        # 6. Recommandations SOC
        # ----------------------------------------------------
        story.append(Paragraph("6. Recommandations SOC", self.styles['SectionTitle']))
        
        reco_data = [["#", "Action", "Priorité", "Responsable"]]
        
        if event.get("priority_score") == "CRITICAL":
            reco_data.append(["R1", "Bloquer les IPs/Domaines sur le pare-feu", "IMMÉDIATE", "SOC L1"])
            reco_data.append(["R2", "Lancer un hunting rétrospectif EDR", "HAUTE", "SOC L2"])
            reco_data.append(["R3", "Notifier l'équipe réponse à incident (CSIRT)", "HAUTE", "CISO"])
        elif event.get("priority_score") == "HIGH":
            reco_data.append(["R1", "Bloquer les IOCs sur les équipements de sécurité", "HAUTE", "SOC L1"])
            reco_data.append(["R2", "Surveiller les logs pour détecter l'activité", "MOYENNE", "SOC L2"])
        else:
            reco_data.append(["R1", "Ajouter les IOCs aux listes de surveillance", "BASSE", "SOC L1"])
            reco_data.append(["R2", "Enrichissement passif", "BASSE", "CTI Analyst"])
            
        t_reco = Table(reco_data, colWidths=[1*cm, 9.5*cm, 2.5*cm, 3*cm])
        t_reco.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_reco)

        doc.build(story, onFirstPage=self.header_footer, onLaterPages=self.header_footer)
        return filename

def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    input_file = os.path.join(base_dir, "output_correlation", "correlated_events_soc_enriched.json")
    output_dir = os.path.join(base_dir, "reports", "cti_bulletins")
    
    if not os.path.exists(input_file):
        print(f"File not found: {input_file}")
        return
        
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            events = json.load(f)
    except Exception as e:
        print(f"Error loading events: {e}")
        return
        
    generator = CTIBulletinGenerator(output_dir=output_dir)
    count = 0
    
    for event in events:
        if event.get("priority_score") in ["CRITICAL", "HIGH"]:
            print(f"Generating PDF for {event.get('group_id')} ({event.get('priority_score')})...")
            try:
                pdf_path = generator.generate_pdf(event)
                print(f" -> Saved to {pdf_path}")
                count += 1
            except Exception as e:
                print(f" -> Error generating PDF: {e}")
                
    print(f"\nDone. Generated {count} PDF bulletins in {output_dir}")

if __name__ == "__main__":
    main()
