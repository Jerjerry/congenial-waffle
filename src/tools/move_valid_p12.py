from cryptography.hazmat.primitives.serialization import pkcs12
import os
import sys
from pathlib import Path
import shutil

def validate_p12(file_path, password=None):
    try:
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
            
        if not file_path.lower().endswith('.p12'):
            return False, f"Not a .p12 file: {file_path}"
            
        # Convert password to bytes if provided
        password_bytes = password.encode() if password else None
        
        # Try to load the .p12 file
        with open(file_path, 'rb') as f:
            pkcs12.load_key_and_certificates(f.read(), password_bytes)
            
        return True, "Valid .p12 file"
        
    except Exception as e:
        return False, f"Invalid .p12 file: {str(e)}"

def move_valid_p12_files(directory_path):
    """
    Move valid .p12 files to the root directory.
    """
    directory = Path(directory_path)
    
    # Track statistics
    moved_files = 0
    
    print(f"Scanning directory: {directory}")
    print("Moving valid .p12 files to root directory...")
    
    # Process all .p12 files in directory and subdirectories
    for p12_file in directory.rglob('*.p12'):
        # Skip files that are already in the root directory
        if p12_file.parent == directory:
            continue
            
        is_valid, message = validate_p12(str(p12_file))
        
        if is_valid:
            # Create a unique filename if necessary
            new_name = p12_file.name
            target_path = directory / new_name
            counter = 1
            while target_path.exists():
                new_name = f"{p12_file.stem}_{counter}{p12_file.suffix}"
                target_path = directory / new_name
                counter += 1
            
            print(f"Moving: {p12_file.relative_to(directory)} -> {new_name}")
            shutil.move(str(p12_file), str(target_path))
            moved_files += 1
    
    # Print summary
    print("\nSummary:")
    print(f"Valid files moved to root directory: {moved_files}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python move_valid_p12.py <directory_path>")
        sys.exit(1)
        
    path = sys.argv[1]
    
    if not os.path.isdir(path):
        print("Error: Please provide a valid directory path")
        sys.exit(1)
        
    move_valid_p12_files(path)

if __name__ == "__main__":
    main()
