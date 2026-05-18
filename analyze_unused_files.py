import os
import re

project_dir = r'c:\Users\Hicham\Desktop\PFE\dispostion_CTi'
exclude_dirs = ['misp-docker', 'env', 'frontend\\node_modules', 'frontend\\.next', '.git', '__pycache__']

all_files = []
# Find all files in a single pass
for root, dirs, files in os.walk(project_dir):
    # filter exclude dirs
    dirs[:] = [d for d in dirs if not any(ex in os.path.join(root, d) for ex in exclude_dirs)]
    for f in files:
        if f.endswith(('.py', '.bat', '.sh', '.json', '.js', '.ts', '.tsx', '.jsx')):
            all_files.append(os.path.join(root, f))

# Separate python files
all_py_files = [f for f in all_files if f.endswith('.py')]

# Map filename without extension to its full path
filename_to_paths = {}
for path in all_py_files:
    name = os.path.splitext(os.path.basename(path))[0]
    if name not in filename_to_paths:
        filename_to_paths[name] = []
    filename_to_paths[name].append(path)

# Extract content of all files to search for references
file_contents = {}
for path in all_files:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            file_contents[path] = f.read()
    except Exception:
        pass

unused_files = []
for name, paths in filename_to_paths.items():
    # skip well known or single-letter names to avoid false positives
    if len(name) <= 2 or name in ['run_pipeline', 'run_platform', 'main', '__init__', 'setup']:
        continue
    
    is_referenced = False
    for path, content in file_contents.items():
        if path in paths:
            continue
        
        # Look for word boundaries
        if re.search(r'\b' + re.escape(name) + r'\b', content):
            is_referenced = True
            break
            
    if not is_referenced:
        unused_files.extend(paths)

print("Orphan / Unused Python Files found:")
for f in sorted(unused_files):
    print(f)

print("\nArchived / Backup Folders / Test Folders:")
for root, dirs, files in os.walk(project_dir):
    dirs[:] = [d for d in dirs if not any(ex in os.path.join(root, d) for ex in exclude_dirs)]
    root_lower = root.lower()
    if 'archive' in root_lower or 'copy' in root_lower or 'scratch' in root_lower or 'test' in root_lower:
        print(root)
