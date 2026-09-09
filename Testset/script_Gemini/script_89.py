import os 
  
def change_permissions(filename): 
   # Get the current permissions. 
   current_permissions = os.stat(filename).st_mode 
  
   # Set the new permissions to read-only for the owner. 
   new_permissions = current_permissions & ~os.O_RDWR 
  
   # Set the new permissions. 
   os.chmod(filename, new_permissions) 
  
  
filename = 'priv_file' 
  
change_permissions(filename)
