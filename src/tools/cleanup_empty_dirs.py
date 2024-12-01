import os
import sys
from pathlib import Path

def remove_empty_dirs(directory_path):
    """
    Remove empty directories recursively.
    """
    directory = Path(directory_path)
    
    # Track statistics
    removed_dirs = 0
    
    print(f"Scanning for empty directories in: {directory}")
    
    # Walk bottom-up so we process deepest directories first
    for dirpath, dirnames, filenames in os.walk(str(directory), topdown=False):
        # Skip the root directory
        if dirpath == str(directory):
            continue
            
        if not os.listdir(dirpath):  # Directory is empty
            dir_to_remove = Path(dirpath)
            print(f"Removing empty directory: {dir_to_remove.relative_to(directory)}")
            os.rmdir(dirpath)
            removed_dirs += 1
    
    # Print summary
    print("\nSummary:")
    print(f"Empty directories removed: {removed_dirs}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python cleanup_empty_dirs.py <directory_path>")
        sys.exit(1)
        
    path = sys.argv[1]
    
    if not os.path.isdir(path):
        print("Error: Please provide a valid directory path")
        sys.exit(1)
        
    remove_empty_dirs(path)

if __name__ == "__main__":
    main()
