# Import the os module to use the path and listdir functions
import os

# Define a function that takes a file id as an argument
def check_output_file(file_id):
    # Assume the output files are stored in a directory called "output"
    output_dir = "output"
    # Loop through the files in the output directory
    for file_name in os.listdir(output_dir):
        # Check if the file name starts with the file id
        if file_name.startswith(file_id):
            # Return the full path of the file
            return os.path.join(output_dir, file_name)
    # If no file matches the file id, return None
    return None

# Test the function with a sample file id
file_id = "123456"
output_file = check_output_file(file_id)
if output_file:
    print("Output file found:", output_file)
else:
    print("Output file not found")
