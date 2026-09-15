import os
 
 # Define the file path
file_path = 'path/to/your/file'
 
 # Change the file permission to read-only
os.chmod(file_path, 0o444)
