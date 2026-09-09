import os 
  
def change_permissions(filename, mode): 
   # Get the current permissions. 
   current_permissions = os.stat(filename).st_mode 
  
   # Set the new permissions. 
   os.chmod(filename, mode) 
  
  
filename = 'private' 
  
mode = 0o600 
  
change_permissions(filename, mode)
