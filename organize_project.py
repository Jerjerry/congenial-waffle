import os
import shutil

def organize_project():
    # Create necessary directories
    dirs_to_create = ['archive', 'src']
    for d in dirs_to_create:
        os.makedirs(d, exist_ok=True)

    # Files to archive (old/redundant files)
    files_to_archive = [
        'gui.py',
        'gui_app.py',
        'resign_gui.py',
        'simple_gui.py',
        'sign_ipa.py',
        'resign_ipa.py',
    ]

    # Move files to archive
    for file in files_to_archive:
        if os.path.exists(file):
            shutil.move(file, os.path.join('archive', file))
            print(f"Archived: {file}")

    # Keep only the latest Windows implementation
    core_files = [
        'windows_signer.py',
        'windows_gui.py',
        'tools',
    ]

    # Move core files to src
    for file in core_files:
        if os.path.exists(file):
            dest = os.path.join('src', file)
            if os.path.exists(dest):
                shutil.rmtree(dest) if os.path.isdir(file) else os.remove(dest)
            shutil.move(file, dest)
            print(f"Moved to src: {file}")

    # Update imports in the GUI file
    gui_path = os.path.join('src', 'windows_gui.py')
    if os.path.exists(gui_path):
        with open(gui_path, 'r') as f:
            content = f.read()
        
        # Update import
        content = content.replace(
            'from windows_signer import WindowsIPASigner',
            'from .windows_signer import WindowsIPASigner'
        )
        
        with open(gui_path, 'w') as f:
            f.write(content)
        print("Updated imports in windows_gui.py")

    # Clean up log files
    log_files = [
        'debug.log',
        'ipa_signer_debug.log',
        'signer.log'
    ]
    
    for log in log_files:
        if os.path.exists(log):
            os.remove(log)
            print(f"Removed log file: {log}")

    # Create new main.py
    main_content = """import sys
import os
from src.windows_gui import WindowsSignerGUI

def main():
    app = WindowsSignerGUI()
    app.run()

if __name__ == "__main__":
    main()
"""
    
    with open('main.py', 'w') as f:
        f.write(main_content)
    print("Created main.py")

    # Update requirements.txt
    requirements = """cryptography>=41.0.0
tkinter
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    print("Updated requirements.txt")

if __name__ == "__main__":
    organize_project()
    print("\nProject organization complete!")
    print("You can now run the application using: python main.py")
