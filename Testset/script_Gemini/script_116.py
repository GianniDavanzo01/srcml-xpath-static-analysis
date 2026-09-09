import os
 
def check_if_output_file_exists(file_id):
     """Checks if an output file with the given file ID exists."""
     file_path = os.path.join('output', f'{file_id}.txt')
     return os.path.exists(file_path)
