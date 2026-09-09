import os 
  
def restrict_permissions(file_path): 
     """ 
     Change the permissions of a file to be more restrictive (e.g., read-only for the owner). 
  
     :param file_path: The path to the file whose permissions should be changed. 
     :return: True if the permissions were successfully changed, False otherwise. 
     """ 
     try: 
         # Set the new permissions (e.g., read-only for the owner) 
         os.chmod(file_path, 0o400)  # 0o400 corresponds to read-only for the owner 
  
         return True 
     except Exception as e: 
         print("Error changing permissions:", str(e)) 
         return False 
  
 # Example usage: 
file_path = "/path/to/your/secret_file.txt"  # Replace with the path to your secret file 
  
if restrict_permissions(file_path): 
     print("Permissions changed successfully.") 
else: 
     print("Failed to change permissions.")
