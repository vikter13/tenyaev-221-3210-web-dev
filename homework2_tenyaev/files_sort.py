import os
import sys

def list_files(directory):
    files = {}
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            extension = os.path.splitext(filename)[1]
            if extension not in files:
                files[extension] = []
            files[extension].append(filename)
    
    for extension in sorted(files.keys()):
        print('\n'.join(sorted(files[extension])))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python files_sort.py <directory>")
        sys.exit(1)
    
    directory = sys.argv[1]
    list_files(directory)
