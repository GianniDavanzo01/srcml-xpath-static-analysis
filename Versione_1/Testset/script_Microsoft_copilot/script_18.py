import os 
  
 # Define the path to the directory 
dir_path = '/home' 
  
 # Create the directory 
os.makedirs(dir_path, exist_ok=True) 
  
 # Change the permissions of the directory to allow the user to read from it 
os.chmod(dir_path, 0o755)
