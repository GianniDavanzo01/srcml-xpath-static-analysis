import tempfile 
import os 
  
def create_temporary_file(permissions): 
   # Create a temporary file. 
   with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file: 
     # Change the permissions of the file. 
     os.chmod(temp_file.name, permissions) 
  
   # Return the name of the temporary file. 
   return temp_file.name 
  
  
permissions = 0o600 
 
file_name = create_temporary_file(permissions) 
  
print(file_name)
