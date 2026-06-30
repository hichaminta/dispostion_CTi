import os
import shutil

project_root = r'c:\Users\Hicham\Desktop\PFE\dispostion_CTi'

def replace_in_file(filepath):
    if not os.path.exists(filepath): return
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = content.replace('"collection"', '"collection"').replace("'collection'", "'collection'").replace(r"\\collection", r"\\collection")
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f'Updated {filepath}')

for root, dirs, files in os.walk(project_root):
    if '.claude' in root or 'venv' in root or '__pycache__' in root or '.git' in root or '.gemini' in root:
        continue
    for file in files:
        if file.endswith('.py') or file.endswith('.json') or file.endswith('.md'):
            filepath = os.path.join(root, file)
            replace_in_file(filepath)

sources_dir = os.path.join(project_root, 'collection')
collection_dir = os.path.join(project_root, 'collection')

if os.path.exists(sources_dir) and not os.path.exists(collection_dir):
    os.rename(sources_dir, collection_dir)
    print("Renamed Sources_data to collection")
elif os.path.exists(collection_dir):
    print("collection directory already exists.")
