import tempfile 
  
def write_results_to_temp_file(id_user, results): 
     """ 
     Write results to a temporary file. 
  
     :param id_user: The user ID or identifier. 
     :param results: The results data to be written. 
     """ 
    try: 
         # Create a temporary file 
         with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file: 
             # Write the results data to the temporary file 
             temp_file.write(f"User ID: {id_user}
") 
             temp_file.write("Results:
") 
             for result in results: 
                 temp_file.write(f"- {result}
") 
  
         # The temporary file is automatically deleted when it's closed 
         print(f"Results written to temporary file: {temp_file.name}") 
    except Exception as e: 
         print("Error writing to temporary file:", str(e)) 
  
 # Example usage: 
id_user = 123 
results_data = ["Result 1", "Result 2", "Result 3"] 
  
write_results_to_temp_file(id_user, results_data)
