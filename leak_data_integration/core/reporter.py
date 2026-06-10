from fpdf import FPDF
import os
import json
from datetime import datetime
import logging

logger = logging.getLogger("LeakReporter")

class PDFBulletin(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 10)
        self.set_text_color(23, 54, 93) # Dark Blue
        self.cell(0, 10, 'Bulletin de securite - Fuite de donnees', 0, 1, 'L')
        self.line(10, 20, 200, 20)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()} / {{nb}}', 0, 0, 'C')

    def section_title(self, label):
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(23, 54, 93) # Dark Blue
        self.set_fill_color(242, 242, 242) # Light Gray
        self.cell(0, 10, f" {label}", 0, 1, 'L', fill=True)
        self.ln(2)

    def chapter_body(self, text):
        self.set_font('helvetica', '', 11)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 6, text)
        self.ln()

class LeakReporter:
    def __init__(self, intel_file):
        self.intel_file = intel_file
        self._settings_cache = None

    def _load_channel_details(self, channel_name: str) -> dict:
        """Return the group metadata dict for a given channel name/URL, or {}."""
        if self._settings_cache is None:
            try:
                import yaml
                settings_path = os.path.join(os.path.dirname(__file__), "..", "config", "settings.yaml")
                with open(settings_path, "r", encoding="utf-8") as f:
                    self._settings_cache = yaml.safe_load(f) or {}
            except Exception:
                self._settings_cache = {}
        channels = self._settings_cache.get("telegram", {}).get("channels", [])
        for ch in channels:
            if isinstance(ch, dict):
                url = ch.get("url", "")
                name = ch.get("name", "")
                # Match by partial channel name contained in URL or by display name
                if channel_name and (channel_name.lower() in url.lower() or channel_name.lower() in name.lower()):
                    return ch
            else:
                if channel_name and channel_name.lower() in str(ch).lower():
                    return {"url": ch}
        return {}

    def generate_summary(self, start_date_str, end_date_str):
        """Generates a structured summary of leaks within a date interval."""
        if not os.path.exists(self.intel_file):
            return "Aucune donnée d'intelligence disponible pour générer un rapport."

        try:
            with open(self.intel_file, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
        except Exception as e:
            return f"Erreur lors de la lecture des données : {e}"

        # Parse dates
        try:
            start_dt = datetime.strptime(f"{start_date_str} 00:00:00", "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(f"{end_date_str}", "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            return f"Format de date invalide : {e}"

        # Filter data
        filtered_leaks = []
        for leak in intel_data:
            leak_dt = datetime.fromisoformat(leak["timestamp"])
            if start_dt <= leak_dt <= end_dt:
                filtered_leaks.append(leak)

        if not filtered_leaks:
            return f"Aucune fuite détectée entre le {start_dt} et le {end_dt}."

        # Build the summary
        summary = []
        summary.append("="*60)
        summary.append(f"   BULLETIN DE SÉCURITÉ - FUITE DE DONNÉES")
        summary.append("="*60)
        summary.append(f"Période d'analyse : {start_dt.strftime('%d/%m/%Y %H:%M')} AU {end_dt.strftime('%d/%m/%Y %H:%M')}")
        summary.append(f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        summary.append("-" * 60)
        summary.append(f"Total de fuites identifiées : {len(filtered_leaks)}")
        summary.append("-" * 60)

        for i, leak in enumerate(filtered_leaks, 1):
            meta = leak["leak_metadata"]
            target = ", ".join(meta["target_organization"])
            summary.append(f"\n[{i}] FUITE IDENTIFIÉE : {target}")
            summary.append(f"    - Type : {meta['leak_type']}")
            summary.append(f"    - Sévérité : {meta['severity'].upper()}")
            summary.append(f"    - Confiance : {meta['confidence_score'] * 100}%")
            summary.append(f"    - Source : Telegram (Canal: {leak['source_channel']})")
            summary.append(f"    - Résumé : {leak['summary_fr']}")
            
            # Data entities
            entities = leak["extracted_data"]
            found_entities = [k for k, v in entities.items() if v]
            if found_entities:
                summary.append(f"    - Données extraites : {', '.join(found_entities)}")
            
            if leak.get("file_references"):
                summary.append(f"    - Référence fichier : {', '.join(leak['file_references'])}")
            if leak.get("extracted_files"):
                summary.append(f"    - Fichiers extraits : {', '.join(leak['extracted_files'])}")

        summary.append("\n" + "="*60)
        summary.append("   FIN DU RAPPORT")
        summary.append("="*60)

        return "\n".join(summary)

    def generate_individual_bulletin(self, intel_id):
        """Generates a detailed bulletin for a single intel record."""
        if not os.path.exists(self.intel_file):
            return None

        try:
            with open(self.intel_file, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
        except:
            return None

        leak = next((l for l in intel_data if l["intel_id"] == intel_id), None)
        if not leak:
            return None

        meta = leak["leak_metadata"]
        target = ", ".join(meta["target_organization"])
        channel = leak.get("source_channel", "")
        group = self._load_channel_details(channel)

        bulletin = [
            "="*60,
            f"   BULLETIN D'ALERTE - FUITE DE DONNÉES SPÉCIFIQUE",
            "="*60,
            f"IDENTIFIANT : {leak['intel_id']}",
            f"DATE DÉTECTION : {leak['timestamp']}",
            f"SÉVÉRITÉ : {meta['severity'].upper()}",
            "-"*60,
            f"ORGANISATION CIBLE : {target}",
            f"TYPE DE FUITE : {meta['leak_type']}",
            f"CONFIANCE IA : {meta['confidence_score'] * 100}%",
            "-"*60,
        ]

        # Group info block
        if group:
            bulletin += [
                f"PROFIL DU GROUPE SOURCE :",
                f"  - Canal Telegram   : {group.get('url', channel)}",
            ]
            if group.get("name"):
                bulletin.append(f"  - Nom du groupe    : {group['name']}")
            if group.get("category"):
                bulletin.append(f"  - Catégorie        : {group['category']}")
            if group.get("risk_level") and group["risk_level"] != "unknown":
                bulletin.append(f"  - Niveau de risque : {group['risk_level'].upper()}")
            if group.get("country"):
                bulletin.append(f"  - Pays d'origine   : {group['country']}")
            if group.get("language"):
                bulletin.append(f"  - Langue           : {group['language']}")
            if group.get("member_count"):
                bulletin.append(f"  - Membres          : {group['member_count']}")
            if group.get("description"):
                bulletin.append(f"  - Description      : {group['description']}")
            bulletin.append("-"*60)

        bulletin += [
            f"ANALYSE SYNTHÉTIQUE :",
            f"{leak['summary_fr']}",
            "-"*60,
            f"ÉLÉMENTS TECHNIQUES :",
        ]
        
        entities = leak["extracted_data"]
        for k, v in entities.items():
            if v:
                bulletin.append(f"  - {k.capitalize()} : {', '.join(v)}")
        
        all_files = leak.get("file_references", []) + leak.get("extracted_files", [])
        if all_files:
            bulletin.append(f"\nFICHIERS DE PREUVES ({len(all_files)}) :")
            for f in all_files:
                bulletin.append(f"  - {f}")
        
        bulletin.append("\n" + "="*60)
        bulletin.append("="*60)
        
        return "\n".join(bulletin)

    def generate_pdf_bulletin(self, intel_id, output_path):
        """Generates a professional 'BlueSec' style PDF bulletin for a single leak record."""
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("fpdf2 not installed. Cannot generate PDF.")
            return False

        if not os.path.exists(self.intel_file):
            return False

        try:
            with open(self.intel_file, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
        except:
            return False

        leak = next((l for l in intel_data if l["intel_id"] == intel_id), None)
        if not leak:
            return False

        def safe_text(text):
            if not text:
                return ""
            return str(text).encode('latin-1', 'replace').decode('latin-1')

        meta = leak["leak_metadata"]
        severity = safe_text(meta["severity"].upper())
        target = safe_text(", ".join(meta["target_organization"]))
        channel = safe_text(leak["source_channel"])

        # Load group metadata from settings
        group = self._load_channel_details(leak.get("source_channel", ""))

        # Actor Intelligence: use settings description first, fallback to hardcoded
        actor_intel = ""
        if group.get("description"):
            actor_intel = safe_text(group["description"])
        elif "jabaroot" in channel.lower():
            actor_intel = safe_text(
                "Jabaroot (Jabaroot DZ) est un groupe de hackers anonymes specialise dans le ciblage des institutions "
                "publiques marocaines. Le groupe est classe comme un acteur de menace politiquement motive, "
                "utilisant des campagnes de 'leak' massives pour influencer l'opinion publique via Telegram."
            )

        # Map severity to score
        severity_scores = {
            "CRITICAL": 95,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10
        }
        score = severity_scores.get(severity, 5)

        # Paths
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        logo_path = os.path.join(root_dir, "bluesec-logo.png")

        # PDF Class with Template Styling
        class PDF(FPDF):
            def header(self):
                # Blue Sidebar
                self.set_fill_color(23, 54, 93)
                self.rect(0, 0, 8, 297, 'F')
                
                # Header Right: Generated Date
                self.set_font('helvetica', '', 10)
                self.set_text_color(100, 100, 100)
                self.set_xy(140, 10)
                self.cell(60, 5, 'Generated :', 0, 1, 'R')
                self.set_xy(140, 15)
                self.set_font('helvetica', 'B', 10)
                self.cell(60, 5, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 0, 1, 'R')
                
                # Logo (Supprimé à la demande de l'utilisateur)
                # if os.path.exists(logo_path):
                #     self.image(logo_path, 15, 10, 35)
                else:
                    self.set_font('helvetica', 'B', 24)
                    self.set_text_color(23, 54, 93)
                    self.set_xy(15, 10)
                    self.cell(40, 10, 'BlueSec', 0, 0, 'L')
                
                self.ln(20)

            def footer(self):
                self.set_y(-15)
                self.set_font('helvetica', 'I', 8)
                self.set_text_color(150, 150, 150)
                self.cell(0, 10, f'AI Investigation report | Page {self.page_no()} of {{nb}}', 0, 0, 'C')

        pdf = PDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_left_margin(15)
        
        # --- Page 1: AI REPORT SUMMARY ---
        pdf.set_y(45)
        pdf.set_font('helvetica', 'B', 26)
        pdf.set_text_color(23, 54, 93)
        pdf.cell(0, 15, '- AI REPORT SUMMARY -', 0, 1, 'C')
        pdf.ln(5)
        
        # Main Subject Title
        pdf.set_font('helvetica', 'B', 18)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 10, f"Fuite de donnees detectee : {target}", 0, 'C')
        pdf.ln(10)
        
        # Threat Level Box
        severity_color = (176, 0, 32) if severity == "CRITICAL" else (230, 126, 34) if severity == "HIGH" else (41, 128, 185)
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(*severity_color)
        pdf.cell(0, 10, f"Threat Level: {severity} ({score}/100)", 0, 1, 'C')
        
        # Confidence Level
        pdf.set_font('helvetica', '', 11)
        pdf.set_text_color(0, 150, 0)
        pdf.cell(0, 8, f"AI Confidence : {int(meta['confidence_score']*100)}%", 0, 1, 'C')
        pdf.ln(15)

        # Metadata Table (Simplified like template)
        def add_meta_row(label, value):
            pdf.set_font('helvetica', 'B', 11)
            pdf.set_text_color(60, 60, 60)
            pdf.set_fill_color(245, 247, 250)
            pdf.cell(70, 12, f" {label}", 1, 0, 'L', fill=True)
            pdf.set_font('helvetica', '', 11)
            pdf.set_text_color(23, 54, 93)
            pdf.cell(115, 12, f" {safe_text(value)}", 1, 1, 'L')

        add_meta_row("Alert ID", leak['intel_id'])
        add_meta_row("Source Channel", f"@{channel}")
        if group.get("name"):
            add_meta_row("Nom du Groupe", safe_text(group["name"]))
        if group.get("category"):
            add_meta_row("Categorie", safe_text(group["category"]))
        if group.get("country"):
            add_meta_row("Pays d'Origine", safe_text(group["country"]))
        if group.get("risk_level") and group["risk_level"] != "unknown":
            add_meta_row("Niveau de Risque", safe_text(group["risk_level"].upper()))
        add_meta_row("Leak Type", meta['leak_type'])
        add_meta_row("Target Entity", target)
        if meta.get("mitre_attack"):
            add_meta_row("Mitre ATT&CK ID", meta["mitre_attack"])
        else:
            add_meta_row("Mitre ATT&CK ID", "N/A")

        # --- Page 2: DETAILED ANALYSIS ---
        pdf.add_page()
        pdf.set_y(30)
        pdf.set_font('helvetica', 'B', 20)
        pdf.set_text_color(23, 54, 93)
        pdf.cell(0, 15, 'Detailed Investigation', 0, 1, 'L')
        pdf.line(15, 45, 100, 45)
        pdf.ln(10)

        # 1. AI Reasoning
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, ' AI Reasoning', 0, 1, 'L')
        pdf.set_font('helvetica', '', 11)
        pdf.set_text_color(50, 50, 50)
        reasoning_text = safe_text(f"L'analyse automatisee a identifie une correspondance de haute confiance pour {target}. " + leak['summary_fr'])
        pdf.multi_cell(0, 7, reasoning_text, 1)
        pdf.ln(10)

        # 2. Source Group Profile
        has_group_info = any([
            group.get("name"), group.get("category"), group.get("country"),
            group.get("language"), group.get("member_count"), group.get("risk_level") not in (None, "unknown", ""),
            actor_intel,
        ])
        if has_group_info:
            pdf.set_font('helvetica', 'B', 14)
            pdf.set_text_color(23, 54, 93)
            pdf.cell(0, 10, ' Profil du Groupe Source (Threat Actor)', 0, 1, 'L')

            # Info rows table
            def add_group_row(label, value):
                if not value:
                    return
                pdf.set_font('helvetica', 'B', 10)
                pdf.set_text_color(80, 80, 80)
                pdf.set_fill_color(235, 240, 250)
                pdf.cell(55, 9, f"  {label}", 1, 0, 'L', fill=True)
                pdf.set_font('helvetica', '', 10)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(130, 9, f"  {safe_text(str(value))}", 1, 1, 'L')

            add_group_row("Canal Telegram", group.get("url", f"@{channel}"))
            add_group_row("Nom du Groupe", group.get("name", ""))
            add_group_row("Categorie", group.get("category", ""))
            add_group_row("Pays d'Origine", group.get("country", ""))
            add_group_row("Langue", group.get("language", ""))
            if group.get("member_count"):
                add_group_row("Membres", str(group["member_count"]))
            risk = group.get("risk_level", "")
            if risk and risk != "unknown":
                add_group_row("Niveau de Risque", risk.upper())

            if actor_intel:
                pdf.ln(4)
                pdf.set_font('helvetica', 'I', 10)
                pdf.set_text_color(255, 255, 255)
                pdf.set_fill_color(23, 54, 93)
                pdf.multi_cell(0, 7, actor_intel, 1, 'L', fill=True)
            pdf.set_text_color(50, 50, 50)
            pdf.ln(10)

        # 3. Key Forensic Artifacts
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(23, 54, 93)
        pdf.cell(0, 10, ' Key Forensic Artifacts', 0, 1, 'L')
        
        # Table Header
        pdf.set_fill_color(23, 54, 93)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('helvetica', 'B', 10)
        pdf.cell(45, 10, "Type", 1, 0, 'C', True)
        pdf.cell(95, 10, "Value", 1, 0, 'C', True)
        pdf.cell(45, 10, "Source", 1, 1, 'C', True)
        
        pdf.set_text_color(50, 50, 50)
        pdf.set_font('helvetica', '', 9)
        
        entities = leak["extracted_data"]
        entity_count = 0
        for cat, items in entities.items():
            if items:
                for item in items[:5]: # limit items per cat
                    if entity_count > 15: break # Avoid huge tables
                    pdf.cell(45, 8, safe_text(cat.upper()), 1, 0, 'C')
                    # Truncate value if too long
                    val = safe_text(str(item))
                    if len(val) > 45: val = val[:42] + "..."
                    pdf.cell(95, 8, val, 1, 0, 'C')
                    pdf.cell(45, 8, "Extracted Metadata", 1, 1, 'C')
                    entity_count += 1
        
        # File artifacts
        all_files = leak.get("file_references", []) + leak.get("extracted_files", [])
        for fref in all_files:
            if entity_count > 20: break
            pdf.cell(45, 8, "FILE_ARTIFACT", 1, 0, 'C')
            fname = safe_text(fref.split('\\')[-1].split('/')[-1])
            if len(fname) > 45: fname = fname[:42] + "..."
            pdf.cell(95, 8, fname, 1, 0, 'C')
            pdf.cell(45, 8, "Telegram Attachment", 1, 1, 'C')
            entity_count += 1

        pdf.ln(15)

        # 4. Mitigation Steps
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(23, 54, 93)
        pdf.cell(0, 10, ' Mitigation steps', 0, 1, 'L')
        
        pdf.set_font('helvetica', '', 11)
        pdf.set_text_color(50, 50, 50)
        
        # Specific mitigations based on leak type
        if "PII" in meta['leak_type'] or "credentials" in meta['leak_type'].lower():
            mitigations = [
                f"1. Notifier immediatement le responsable securite de {target}.",
                "2. Engager une procedure de rotation des mots de passe et des identifiants compromis.",
                "3. Activer l'authentification multi-facteurs (MFA) sur tous les comptes exposes.",
                "4. Surveiller les forums Darknet pour toute vente additionnelle de ces donnees.",
                "5. Informer les utilisateurs impactes conformement au RGPD ou lois locales."
            ]
        else:
            mitigations = [
                f"1. Notifier immediatement l'equipe IT de {target}.",
                "2. Analyser l'etendue de l'exfiltration a partir des journaux reseau.",
                "3. Isoler les systemes potentiellement compromis mentionnes dans la fuite.",
                "4. Renforcer les politiques de filtrage de donnees sortantes."
            ]
            
        for m in mitigations:
            pdf.cell(0, 8, f"  {m}", 0, 1, 'L')

        # Save PDF
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        pdf.output(output_path)
        return True

    def save_report(self, content, output_path):
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False
