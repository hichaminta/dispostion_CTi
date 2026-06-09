import os
from PyPDF2 import PdfReader, PdfWriter

def apply_bulletin_template(input_pdf_path, output_pdf_path, template_pdf_path):
    if not os.path.exists(template_pdf_path):
        print(f"Warning: Template not found at {template_pdf_path}. Skipping template merge.")
        # If no template, just copy or rename the file
        if input_pdf_path != output_pdf_path:
            import shutil
            shutil.copy2(input_pdf_path, output_pdf_path)
        return

    try:
        reader = PdfReader(input_pdf_path)
        template = PdfReader(template_pdf_path)
        writer = PdfWriter()
        
        # Determine template pages (if template has 2 pages, use pg 0 for first, pg 1 for rest)
        template_first_page = template.pages[0]
        template_other_pages = template.pages[1] if len(template.pages) > 1 else template.pages[0]
        
        for i, page in enumerate(reader.pages):
            # Create a fresh copy of the template page for this page
            if i == 0:
                bg_page = PdfReader(template_pdf_path).pages[0]
            else:
                bg_idx = 1 if len(template.pages) > 1 else 0
                bg_page = PdfReader(template_pdf_path).pages[bg_idx]
                
            # Merge the reportlab content OVER the template background
            bg_page.merge_page(page)
            writer.add_page(bg_page)
            
        with open(output_pdf_path, 'wb') as f:
            writer.write(f)
            
    except Exception as e:
        print(f"Error merging template: {e}")
        if input_pdf_path != output_pdf_path:
            import shutil
            shutil.copy2(input_pdf_path, output_pdf_path)
