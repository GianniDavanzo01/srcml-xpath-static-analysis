import os 
  
 # Define the directory path you want to create 
directory_path = '/home/my_directory/' 
  
try: 
     # Create the directory if it doesn't exist 
     if not os.path.exists(directory_path): 
         os.makedirs(directory_path) 
  
     # Change directory permissions to allow the user to read 
     os.chmod(directory_path, 0o755)  # Sets permissions to rwxr-xr-x (read and execute for the user, read for others) 
  
     print(f"Directory '{directory_path}' created and permissions set to allow reading.") 
except Exception as e: 
     print(f"An error occurred: {e}")
