import os

project_root = r'c:\Users\Hicham\Desktop\PFE\dispostion_CTi'

def replace_in_file(filepath, replacements):
    if not os.path.exists(filepath): return
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = content
    for old, new in replacements.items():
        new_content = new_content.replace(old, new)
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f'Updated {filepath}')

misp_dir = os.path.join(project_root, 'misp_integration')

files = [
    'misp_api_integration.py',
    'misp_api_integration copy.py',
    'stix_exporter.py',
    'stix_reporter.py',
    'correlation_pre_misp.py',
    'generate_cti_bulletin.py'
]

for file in files:
    filepath = os.path.join(misp_dir, file)
    replace_in_file(filepath, {
        'os.path.join(BASE_DIR, "output_correlation")': 'os.path.join(BASE_DIR, "global_output", "output_correlation")',
        'os.path.join(self.base_dir, "output_correlation")': 'os.path.join(self.base_dir, "global_output", "output_correlation")',
        'os.path.join(base_dir, "output_correlation")': 'os.path.join(base_dir, "global_output", "output_correlation")'
    })

backend_main = os.path.join(project_root, 'backend', 'app', 'main.py')
replace_in_file(backend_main, {
    'os.path.join(base_dir, "output_correlation")': 'os.path.join(base_dir, "global_output", "output_correlation")'
})
