import tempfile 
  
def write_results_to_temporary_file(id_user, results): 
   # Create a temporary file. 
   with tempfile.NamedTemporaryFile() as f: 
     # Write the results to the file. 
     f.write(results) 
  
   # Return the file name. 
   return f.name 
  
id_user = 123456 
results = "This is the result." 
  
file_name = write_results_to_temporary_file(id_user, results) 
  
print(file_name)
