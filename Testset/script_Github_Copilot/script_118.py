import os

# Define the path to the file
file_path = '/path/to/file'

# Define the new permissions using octal notation (e.g., 0o644 for read/write by owner, read-only by others)
new_permissions = 0o644

try:
    # Change the file permissions
    os.chmod(file_path, new_permissions)
    print(f"Changed permissions of '{file_path}' to {oct(new_permissions)}")
except Exception as e:
    print(f"Failed to change permissions: {str(e)}")
