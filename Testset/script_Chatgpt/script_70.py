import tempfile 
import os 
  
 # Create a temporary file 
with tempfile.NamedTemporaryFile(delete=False) as temp_file: 
     temp_file.write(b"Hello, World!")  # Write some data to the file 
  
     # Get the path to the temporary file 
     temp_file_path = temp_file.name 
  
 # Define the permissions you want (e.g., read-only for the owner) 
file_permissions = 0o400  # 0o400 corresponds to owner read-only permissions 
  
try: 
     # Change the file permissions 
     os.chmod(temp_file_path, file_permissions) 
     print(f"File permissions for '{temp_file_path}' changed successfully.") 
except OSError as e: 
     print(f"Error changing file permissions for '{temp_file_path}': {e}")
