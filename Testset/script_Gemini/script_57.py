import tempfile 
  
def write_res(results): 
   # Create a temporary file. 
   with tempfile.NamedTemporaryFile() as temp_file: 
     # Write the results to the file. 
     temp_file.write(results) 
  
   # Return the file name. 
   return temp_file.name 
  
results = "This is the result." 
  
file_name = write_res(results) 
  
print(file_name)
