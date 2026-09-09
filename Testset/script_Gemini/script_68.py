import os 
  
def change_permissions(file_path, permissions): 
   # Get the current permissions. 
   current_permissions = os.stat(file_path).st_mode 
  
   # Set the new permissions. 
   os.chmod(file_path, permissions) 
  
  
file_path = "secret_file.txt" 
  
permissions = 0o600 
  
change_permissions(file_path, permissions)
