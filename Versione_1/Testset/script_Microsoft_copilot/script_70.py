import os 
import tempfile 
  
def create_temp_file(): 
     temp_file = tempfile.NamedTemporaryFile(delete=False) 
     os.chmod(temp_file.name, 0o400) 
     return temp_file.name
