import os, glob

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

main_py = os.path.join(project_root, 'backend', 'app', 'main.py')
replace_in_file(main_py, {
    '"misp_integration", "tracking", "misp_tracking.json"': '"tracking", "misp_tracking.json"',
    'os.path.join(misp_dir, "misp_tracking.json")': 'os.path.join(base_dir, "tracking", "misp_tracking.json")',
    'os.path.join(base_dir, "misp_integration", "misp_tracking.json")': 'os.path.join(base_dir, "tracking", "misp_tracking.json")',
    'os.path.join(misp_dir, "stix_tracking.json")': 'os.path.join(base_dir, "tracking", "stix_tracking.json")',
    'os.path.join(base_dir, "utils", "local_tracking.json")': 'os.path.join(base_dir, "tracking", "local_tracking.json")',
    'os.path.join(base_dir, "enrichment", "tracking")': 'os.path.join(base_dir, "tracking", "tracking_enrichment")',
})

tracking_py = os.path.join(project_root, 'utils', 'tracking.py')
replace_in_file(tracking_py, {
    'os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_tracking.json")': 'os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tracking", "local_tracking.json")'
})

for root, dirs, files in os.walk(os.path.join(project_root, 'misp_integration')):
    for f in files:
        if f.endswith('.py'):
            replace_in_file(os.path.join(root, f), {
                'os.path.join(BASE_DIR, "misp_integration", "misp_tracking.json")': 'os.path.join(BASE_DIR, "tracking", "misp_tracking.json")',
                'os.path.join(BASE_DIR, "misp_integration", "stix_tracking.json")': 'os.path.join(BASE_DIR, "tracking", "stix_tracking.json")',
            })

for root, dirs, files in os.walk(os.path.join(project_root, 'enrichment')):
    for f in files:
        if f.endswith('.py'):
            replace_in_file(os.path.join(root, f), {
                'os.path.join(BASE_DIR, "enrichment", "tracking")': 'os.path.join(BASE_DIR, "tracking", "tracking_enrichment")'
            })
