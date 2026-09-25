import os

def create_file(filename):
    # Create the directory and any missing parent directories
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Create the empty file
    open(filename, 'a').close()

    print(f"File '{filename}' created successfully.")

# Example usage
create_file('/path/to/new/file.txt')
