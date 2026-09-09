import tempfile 
  
def write_results_to_temp_file(results): 
     temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w+') 
  
     for result in results: 
         temp_file.write(f"{result}
") 
  
     temp_file.seek(0) 
     return temp_file
