import os
 
def check_file(file_id):
     filename = f"{file_id}.txt"  # replace '.txt' with your file extension
     return os.path.isfile(filename)
 
 # Usage
file_id = 'your_file_id_here'  # replace with your file id
if check_file(file_id):
     print(f"The file with ID {file_id} exists.")
else:
     print(f"The file with ID {file_id} does not exist.")
