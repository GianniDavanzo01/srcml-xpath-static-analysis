import os
 
def change_file_permissions(file_path):
     try:
         # Change file permissions (e.g., 0o755 for rwxr-xr-x)
         os.chmod(file_path, 0o755)
 
         print(f"Permissions of '{file_path}' changed to 0o755.")
     except OSError as e:
         print(f"Error changing permissions: {e}")
 
 # Example usage
file_path = 'your_file.txt'  # Replace with the path to your file
 
change_file_permissions(file_path)
