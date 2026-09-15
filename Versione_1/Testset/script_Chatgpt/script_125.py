class User:
     def __init__(self, username):
         self.username = username
         self.is_logged_in = True
 
def logout_user(user):
     """
     Logs out the user by updating the user's state.
 
     Parameters:
     - user: The user object to be logged out.
     """
     user.is_logged_in = False
     print(f"User {user.username} has been logged out.")
 
 # Example usage:
 
 # Create a user
current_user = User("example_user")
 
 # Print the initial state
print(f"Is user {current_user.username} logged in? {current_user.is_logged_in}")
 
 # Log out the user
logout_user(current_user)
 
 # Print the updated state
print(f"Is user {current_user.username} logged in? {current_user.is_logged_in}")
