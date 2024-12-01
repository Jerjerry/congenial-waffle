import os
import shutil
from pathlib import Path

def organize_project():
    base_dir = Path('c:/Users/Admin/CascadeProjects/ipa_signer')
    
    # Create our directory structure
    directories = {
        'certs': base_dir / 'certs',
        'tools': base_dir / 'tools',
        'dylibs': base_dir / 'dylibs',
        'docs': base_dir / 'docs'
    }
    
    # Create directories
    for dir_path in directories.values():
        dir_path.mkdir(exist_ok=True)
        print(f"Created directory: {dir_path}")
    
    # Move certificate files
    cert_source = base_dir / 'Sideload.Tools.main/Sideload-Tools-main/Cert'
    if cert_source.exists():
        for file in cert_source.rglob('*'):
            if file.is_file():
                if file.suffix.lower() == '.p12':
                    dest = directories['certs'] / file.name
                    shutil.copy2(file, dest)
                    print(f"Moved certificate: {file.name}")
    
    # Move dylibs
    dylib_source = base_dir / 'Sideload.Tools.main/Sideload-Tools-main/Dylibs'
    if dylib_source.exists():
        for file in dylib_source.rglob('*'):
            if file.is_file():
                if file.suffix.lower() == '.dylib':
                    dest = directories['dylibs'] / file.name
                    shutil.copy2(file, dest)
                    print(f"Moved dylib: {file.name}")
    
    # Move Python tools
    tool_files = [
        'cleanup_empty_dirs.py',
        'cleanup_invalid_p12.py',
        'easy_sign.py',
        'move_valid_p12.py',
        'p12_validator.py'
    ]
    
    for tool in tool_files:
        src = base_dir / tool
        if src.exists():
            dest = directories['tools'] / tool
            shutil.move(src, dest)
            print(f"Moved tool: {tool}")
    
    # Move documentation
    doc_files = {
        base_dir / 'README.md': 'README.md',
        base_dir / 'Sideload.Tools.main/Sideload-Tools-main/README.md': 'sideload_tools_readme.md'
    }
    
    for src, dest_name in doc_files.items():
        if src.exists():
            dest = directories['docs'] / dest_name
            shutil.copy2(src, dest)
            print(f"Moved documentation: {dest_name}")
    
    # Move requirements.txt to root (it should stay in project root)
    req_src = base_dir / 'requirements.txt'
    if req_src.exists():
        print("Requirements.txt is already in root directory")
    
    # Clean up original directories
    cleanup_dirs = [
        base_dir / 'Sideload.Tools.main',
        base_dir / 'ipa_signer'
    ]
    
    for dir_path in cleanup_dirs:
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"Cleaned up: {dir_path}")
    
    # Create a new README in root with updated structure
    new_readme_content = """# IPA Signer Project

A collection of tools for signing iOS IPA files using certificates.

## Project Structure

- `certs/`: Contains .p12 certificate files for signing
- `tools/`: Python scripts for certificate validation and IPA signing
- `dylibs/`: Dynamic libraries that can be injected into apps
- `docs/`: Project documentation

## Quick Start

1. Install requirements:
   ```
   pip install -r requirements.txt
   ```

2. Sign an IPA file:
   ```
   python tools/easy_sign.py your_app.ipa
   ```

## Available Tools

- `easy_sign.py`: Main tool for signing IPA files
- `p12_validator.py`: Validates .p12 certificate files
- `cleanup_invalid_p12.py`: Removes invalid certificates
- `move_valid_p12.py`: Organizes valid certificates
- `cleanup_empty_dirs.py`: Cleans up empty directories

## Certificates

Valid certificates are stored in the `certs/` directory. Use `tools/p12_validator.py` to verify certificates.

## Documentation

See the `docs/` directory for detailed documentation and guides."""

    with open(base_dir / 'README.md', 'w') as f:
        f.write(new_readme_content)
    print("Created new README.md")
    
    print("\nProject organization complete!")
    print("\nNew structure:")
    print("- certs/: Certificate files")
    print("- tools/: Python scripts")
    print("- dylibs/: Dynamic libraries")
    print("- docs/: Documentation")
    print("- requirements.txt: Dependencies")
    print("- README.md: Project overview")

if __name__ == '__main__':
    organize_project()
