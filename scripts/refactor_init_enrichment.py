import os
import re

filepath = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\enrichment\initialize_enrichment.py"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the input directory definition
content = re.sub(
    r'INPUT_DIR = os\.path\.join\(BASE_DIR, "__TEMP__/global_output/output_cve_ioc"\)',
    'GLOBAL_SOURCES_DIR = os.path.join(BASE_DIR, "global_output", "sources")',
    content
)
content = re.sub(
    r'OUTPUT_DIR = os\.path\.join\(BASE_DIR, "__TEMP__/global_output/output_enrichment"\)',
    '',
    content
)

# Replace the file gathering block
old_files_block = """    if not os.path.exists(INPUT_DIR):
        logger.error(f"Dossier d'entrǸe introuvable : {INPUT_DIR}")
        return

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"CrǸation du dossier de sortie : {OUTPUT_DIR}")

    files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".json")]
    
    if source_filter:
        files = [f for f in files if source_filter.lower() in f.lower()]
        logger.info(f"Filtrage pour la source : {source_filter}")
    
    if not files:
        logger.warning(f"Aucun fichier JSON trouvǸ dans {INPUT_DIR}")
        return"""

new_files_block = """    import glob
    if not os.path.exists(GLOBAL_SOURCES_DIR):
        logger.error(f"Dossier d'entrǸe introuvable : {GLOBAL_SOURCES_DIR}")
        return

    files = glob.glob(os.path.join(GLOBAL_SOURCES_DIR, "*", "extraction", "*.json"))
    
    if source_filter:
        files = [f for f in files if source_filter.lower() in f.lower()]
        logger.info(f"Filtrage pour la source : {source_filter}")
    
    if not files:
        logger.warning(f"Aucun fichier JSON trouvǸ dans extraction")
        return"""

content = content.replace(old_files_block, new_files_block)

# Replace loop initialization
old_loop_init = """    count = 0
    for filename in files:
        src_path = os.path.join(INPUT_DIR, filename)"""

new_loop_init = """    count = 0
    for src_path in files:
        filename = os.path.basename(src_path)
        source_name = os.path.basename(os.path.dirname(os.path.dirname(src_path)))
        OUTPUT_DIR = os.path.join(GLOBAL_SOURCES_DIR, source_name, "enrichment")
        os.makedirs(OUTPUT_DIR, exist_ok=True)"""

content = content.replace(old_loop_init, new_loop_init)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)

print("Updated initialize_enrichment.py")
