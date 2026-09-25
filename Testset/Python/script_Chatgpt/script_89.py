import os 
  
 # Specify the file path 
file_path = 'priv_file'  # Replace with the actual path to your 'priv_file' 
  
 # Define the read-only permissions for the owner (owner can read, others cannot) 
read_only_permissions = 0o400  # 0o400 corresponds to owner read-only permissions 
  
try: 
     # Change the file permissions to read-only for the owner 
     os.chmod(file_path, read_only_permissions) 
     print(f"Permissions for '{file_path}' changed to read-only for the owner.") 
except OSError as e: 
     print(f"Error changing permissions for '{file_path}': {e}")
