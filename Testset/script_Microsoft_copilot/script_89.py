import os 
  
 # Set the permissions of the file to read-only for the owner 
os.chmod('priv_file', 0o400)
