import os
 
def is_output_file_exists(file_id):
     # Define the directory or path where your output files are stored
     output_directory = '/path/to/your/output/files'
 
     # Assuming a naming convention or structure for file IDs
     file_path = os.path.join(output_directory, f'output_{file_id}.txt')
 
     # Check if the file exists
     return os.path.exists(file_path)
 
 # Example usage
file_id_to_check = '123'
if is_output_file_exists(file_id_to_check):
     print(f"Output file with file ID {file_id_to_check} exists.")
else:
     print(f"Output file with file ID {file_id_to_check} does not exist.")
