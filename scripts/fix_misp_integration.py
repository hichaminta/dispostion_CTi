import os
import glob

misp_dir = r"c:\Users\Hicham\Desktop\PFE\dispostion_CTi\misp_integration"

for filepath in glob.glob(os.path.join(misp_dir, "*.py")):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content = content.replace('__TEMP__/global_output/output_correlation', 'global_output/output_correlation')
        
        if "correlation_pre_misp.py" in filepath:
            # We also need to fix the process_files to use glob for input enrichment files
            # Because it reads from enrichment output
            old_loop = "all_files = [f for f in os.listdir(self.input_dir) if f.endswith('_enriched.json')]"
            new_loop = "import glob\n        all_files = glob.glob(os.path.join(BASE_DIR, 'global_output', 'sources', '*', 'enrichment', '*.json'))"
            new_content = new_content.replace(old_loop, new_loop)
            
            old_for = "for filename in all_files:\n            filepath = os.path.join(self.input_dir, filename)"
            new_for = "for filepath in all_files:\n            filename = os.path.basename(filepath)"
            new_content = new_content.replace(old_for, new_for)
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

print("Fixed misp_integration files")
