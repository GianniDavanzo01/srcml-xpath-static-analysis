import os 
  
 # Specify the file path 
file_path = 'private' 
  
 # Define the restrictive permissions (e.g., read and write for the file owner, no permissions for others) 
restrictive_permissions = 0o600  # 0o600 corresponds to owner read and write permissions 
  
try: 
     # Change the file permissions to restrictive 
     os.chmod(file_path, restrictive_permissions) 
     print(f"Permissions for '{file_path}' changed to restrictive.") 
except OSError as e: 
     print(f"Error changing permissions for '{file_path}': {e}")
