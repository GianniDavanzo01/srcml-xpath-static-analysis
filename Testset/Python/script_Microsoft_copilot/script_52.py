import tempfile 
  
def write_results_to_temp_file(id_user, results): 
     temp_file = tempfile.NamedTemporaryFile(delete=False) 
  
     with open(temp_file.name, 'w') as file: 
         file.write(f"Results for user ID {id_user}:") 
         for result in results: 
             file.write(f"{result}
") 
  
     return temp_file.name
