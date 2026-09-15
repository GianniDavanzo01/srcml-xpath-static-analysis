import os 
  
def set_file_permissions(file_path): 
     os.chmod(file_path, 0o400)
