import tempfile 
  
def write_res(data): 
     """ 
     Create a temporary file and write data to it. 
  
     :param data: The data to be written to the temporary file. 
     :return: The temporary file object. 
     """ 
     try: 
         # Create a temporary file 
         temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False) 
  
         # Write the data to the temporary file 
         temp_file.write(data) 
  
         # Close the temporary file 
         temp_file.close() 
  
         return temp_file 
     except Exception as e: 
         print("Error creating temporary file:", str(e)) 
         return None 
  
 # Example usage: 
data_to_write = "This is some sample data." 
  
temp_file = write_res(data_to_write) 
  
if temp_file: 
     print("Temporary file created:", temp_file.name) 
else: 
     print("Failed to create temporary file.")
