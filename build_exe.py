import PyInstaller.__main__
import sys
import os

def build_exe():
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to the GUI script
    gui_script = os.path.join(script_dir, 'gui_app.py')
    
    # Build the executable
    PyInstaller.__main__.run([
        gui_script,
        '--onefile',
        '--noconsole',
        '--name=IPA_Signer',
        '--icon=NONE',
        '--add-data=tools;tools',  # Include the tools directory
        '--paths=tools',  # Add tools directory to Python path
        '--hidden-import=tools.macho.parser',
        '--hidden-import=tools.macho.codesign',
        '--hidden-import=tools.macho.dylib',
        '--hidden-import=tools.macho.structures',
        '--hidden-import=tools.cert_utils',
        '--hidden-import=tools.pysign',
        '--clean'
    ])

if __name__ == "__main__":
    build_exe()
