import tempfile 
  
 # Create a temporary file. 
with tempfile.NamedTemporaryFile() as temp_file: 
   # Write the results to the file. 
   temp_file.write("This is the result.") 
  
 # Get the file name. 
file_name = temp_file.name 
  
print(file_name)
