import os
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

class LeakBulletinGenerator:
    def __init__(self, output_dir="reports/leak_bulletins"):
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
        
        # Logo BlueSec (Supprimé à la demande de l'utilisateur)
        # logo_path = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\bluesec-logo.png"
        # if os.path.exists(logo_path):
        #     # Le coin inférieur gauche de l'image est à (x, y). On le met à A4[1] - 65 pour ne pas déborder en haut.
        #     canvas.drawImage(logo_path, doc.leftMargin, A4[1] - 65, width=3*cm, height=1.5*cm, preserveAspectRatio=True, mask='auto')
        #     text_x = doc.leftMargin + 3.5*cm
        # else:
        #     text_x = doc.leftMargin
        text_x = doc.leftMargin

        # Header Left: BlueSec
        canvas.setFont('Helvetica-Bold', 12)
        canvas.setFillColor(colors.HexColor("#17365d"))
        canvas.drawString(text_x, A4[1] - 40, "BLUESEC SOC · DATA LEAK INTELLIGENCE")
        
        # Header Right: Confidentiel
        canvas.setFont('Helvetica-Oblique', 9)
        canvas.setFillColor(colors.HexColor("#d32f2f"))
        canvas.drawString(A4[0] - doc.rightMargin - 150, A4[1] - 40, "TLP:RED - Confidentiel")
        
        # Footer
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor("#888888"))
        canvas.drawString(doc.leftMargin, 30, f"Généré par Leak Intelligence Pipeline · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 30, f"Page {doc.page}")
        
        # Lines
        canvas.setStrokeColor(colors.HexColor("#17365d"))
        canvas.setLineWidth(1)
        canvas.line(doc.leftMargin, A4[1] - 75, A4[0] - doc.rightMargin, A4[1] - 75)
        canvas.line(doc.leftMargin, 45, A4[0] - doc.rightMargin, 45)
        
        canvas.restoreState()

    def generate_individual_pdfs(self, leaks):
        generated_files = []
        for i, leak in enumerate(leaks):
            intel_id = leak.get("intel_id", f"UNKNOWN_{i}")
            # Remplacer les caractères invalides pour le nom de fichier
            safe_id = "".join([c if c.isalnum() or c in "-_" else "_" for c in intel_id])
            
            filename = os.path.join(self.output_dir, f"Bulletin_Fuite_{safe_id}.pdf")
            
            doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=3*cm, bottomMargin=2.5*cm)
            story = []

            meta = leak.get("leak_metadata", {})
            orgs = ", ".join(meta.get("target_organization", ["Inconnu"]))
            
            # Titre Principal
            story.append(Paragraph(f"Bulletin de Sécurité : Fuite de données", self.styles['TitleStyle']))
            story.append(Paragraph(f"Cible identifiée : {orgs}", self.styles['SubtitleStyle']))
            story.append(Paragraph(f"Date d'émission : {datetime.now().strftime('%d %B %Y — %H:%MZ')}<br/>TLP:RED - Confidentiel", self.styles['HeaderRight']))
            story.append(Spacer(1, 1*cm))
            
            # Sévérité & Contexte
            severity = meta.get("severity", "LOW").upper()
            severity_color = colors.HexColor("#d32f2f") if severity == "CRITICAL" else (colors.HexColor("#f57c00") if severity == "HIGH" else colors.HexColor("#17365d"))
            
            info_data = [
                ["ID d'Intelligence", leak.get("intel_id", "N/A")],
                ["Sévérité", Paragraph(f"<font color='{severity_color.hexval()}'><b>{severity}</b></font>", self.styles['NormalText'])],
                ["Date de la fuite", leak.get("leak_date", "Inconnue")],
                ["Canal source", leak.get("source_channel", "Inconnu")],
                ["Type de fuite", meta.get("leak_type", "Unknown")],
                ["Score de confiance", f"{meta.get('confidence_score', 0) * 100}%"]
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

            # Résumé FR
            story.append(Paragraph("Résumé de l'incident", self.styles['SubtitleStyle']))
            summary_txt = leak.get("summary_fr", "Aucun résumé disponible.")
            story.append(Paragraph(summary_txt, self.styles['NormalText']))
            story.append(Spacer(1, 0.5*cm))

            # Fichiers extraits
            extracted_files = leak.get("extracted_files", [])
            if extracted_files:
                story.append(Paragraph(f"Fichiers Exfiltrés / Divulgués ({len(extracted_files)})", self.styles['SubtitleStyle']))
                file_table_data = [["Nom du fichier ou chemin (Aperçu)"]]
                for f in extracted_files[:25]:  # Limite pour éviter de trop longues tables
                    if len(f) > 80: f = "..." + f[-77:]
                    file_table_data.append([Paragraph(f, self.styles['NormalText'])])
                
                if len(extracted_files) > 25:
                    file_table_data.append([f"... et {len(extracted_files) - 25} autres fichiers."])
                    
                t_files = Table(file_table_data, colWidths=[16*cm])
                t_files.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#17365d")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(t_files)
            else:
                story.append(Paragraph("Aucun fichier directement extrait mentionné.", self.styles['NormalText']))
            
            story.append(Spacer(1, 1.5*cm))

            doc.build(story, onFirstPage=self.header_footer, onLaterPages=self.header_footer)
            generated_files.append(filename)
            
        return generated_files

def main(input_file=None):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    # Par défaut, chercher dans leak_data_integration/results
    results_dir = os.path.join(base_dir, "leak_data_integration", "results")
    output_dir = os.path.join(base_dir, "reports", "fuite")
    
    if not input_file:
        files = [f for f in os.listdir(results_dir) if f.startswith("leaks_intel") and f.endswith(".json")]
        if not files:
            print("Aucun fichier de résultat leak trouvé.")
            return
        # Prendre le plus récent
        input_file = max([os.path.join(results_dir, f) for f in files], key=os.path.getmtime)
        
    print(f"Lecture des données de fuite : {input_file}")
    
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            leaks = json.load(f)
        print(f"{len(leaks)} rapports de fuite de données extraits.")
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier : {e}")
        return
        
    if not leaks:
        print("Aucune fuite à inclure dans le bulletin.")
        return
        
    generator = LeakBulletinGenerator(output_dir=output_dir)
    print("Génération des Bulletins de Sécurité Individuels (Fuites de Données)...")
    
    try:
        pdf_paths = generator.generate_individual_pdfs(leaks)
        print(f"\n[SUCCÈS] {len(pdf_paths)} Bulletins générés dans {output_dir}")
    except Exception as e:
        print(f"Erreur lors de la génération PDF : {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Générer un Bulletin de Sécurité pour les Fuites de Données")
    parser.add_argument("-i", "--input", help="Fichier JSON des fuites (ex: leaks_intel.json)")
    args = parser.parse_args()
    
    main(input_file=args.input)
