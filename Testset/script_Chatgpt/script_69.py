import os 
  
def make_file_read_only(file_path): 
     """ 
     Change the file permissions to be read-only for the owner. 
  
     :param file_path: The path to the file whose permissions should be changed. 
     :return: True if the permissions were successfully changed, False otherwise. 
     """ 
     try: 
         # Get the current file permissions 
         current_permissions = os.stat(file_path).st_mode 
  
         # Set the new permissions (read-only for the owner) 
         new_permissions = current_permissions & ~0o222  # Remove write permissions 
         os.chmod(file_path, new_permissions) 
  
         return True 
     except Exception as e: 
         print("Error changing permissions:", str(e)) 
         return False 
  
 # Example usage: 
file_path = "/path/to/your/file.txt"  # Replace with the path to your file 
  
if make_file_read_only(file_path): 
     print(f"Permissions for {file_path} changed to read-only for the owner.") 
else: 
     print(f"Failed to change permissions for {file_path}.")
