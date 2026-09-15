import os
 
def create_empty_file(file_path):
     # Ensure the directory structure exists
     os.makedirs(os.path.dirname(file_path), exist_ok=True)
 
     # Create the empty file
     with open(file_path, 'w') as file:
         pass  # Writing nothing creates an empty file
 
 # Example usage
file_path = 'path/to/your/directory/your_file.txt'
 
create_empty_file(file_path)
 
print(f"Empty file created at: {file_path}")
