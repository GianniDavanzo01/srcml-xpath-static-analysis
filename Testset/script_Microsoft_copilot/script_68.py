import os 
  
def set_secret_file_permissions(file_path): 
     os.chmod(file_path, 0o600)
