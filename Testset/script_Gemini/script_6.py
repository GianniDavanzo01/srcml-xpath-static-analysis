def check_credentials(password, id):
    """Checks if the password and ID are equal to effective values.
    
    Args:
      password: The password.
      id: The ID.
      
    Returns:
      True if the password and ID are equal to effective values, False otherwise.
    """
    
    # Get the effective values of the password and ID.
    effective_pass = "secret"
    effective_id = "123456" # Modificato in stringa per matchare l'input()
    
    # Check if the password and ID are equal to the effective values.
    if password == effective_pass and id == effective_id:
        return True
    else:
        return False

if __name__ == "__main__":
    # Get the password and ID from the user.
    password = input("Enter the password: ")
    id = input("Enter the ID: ")
    
    # Check if the password and ID are valid.
    is_valid = check_credentials(password, id)
    
    # Print the result.
    if is_valid:
        print("The credentials are valid.")
    else:
        print("The credentials are invalid.")