import os 
  
def change_permissions(file_path): 
   # Get the current permissions. 
   current_permissions = os.stat(file_path).st_mode 
  
   # Set the new permissions. 
   new_permissions = current_permissions & ~0o22 
  
   # Change the permissions. 
   os.chmod(file_path, new_permissions) 
  
  
file_path = "secret_file.txt" 
  
change_permissions(file_path)
