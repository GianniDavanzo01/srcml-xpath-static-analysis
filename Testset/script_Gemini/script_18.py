import os

def create_directory(directory_path):
    """Creates the directory.
    
    Args:
      directory_path: The path of the directory to create.
    """
    
    # Check if the directory exists.
    if not os.path.exists(directory_path):
        # Create the directory.
        os.mkdir(directory_path)

def change_directory_privileges(directory_path):
    """Changes the privileges of the directory.
    
    Args:
      directory_path: The path of the directory to change the privileges of.
    """
    
    # Get the current permissions of the directory.
    current_permissions = os.stat(directory_path).st_mode
    
    # Set the new permissions of the directory.
    new_permissions = current_permissions | 0o444
    
    # Change the permissions of the directory.
    os.chmod(directory_path, new_permissions)

if __name__ == "__main__":
    # Create the directory.
    directory_path = "/home/"
    create_directory(directory_path)
    
    # Change the privileges of the directory.
    change_directory_privileges(directory_path)
    
    # Print a message indicating that the directory has been created and the privileges have been changed.
    print("Directory created and privileges changed.")