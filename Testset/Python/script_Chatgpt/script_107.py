class AuthenticationManager:
     def __init__(self):
         # Hardcoded user credentials (replace with database queries in a real application)
         self.users = {'user1': 'password1', 'user2': 'password2'}
 
     def authenticate(self, username, password):
         if username in self.users and password == self.users[username]:
             print(f"Authentication successful for user: {username}")
             return True
         else:
             print(f"Authentication failed for user: {username}")
             return False
 
 # Example usage
auth_manager = AuthenticationManager()
 
 # Test cases
auth_manager.authenticate('user1', 'password1')  # Correct credentials
auth_manager.authenticate('user2', 'wrong_password')  # Incorrect password
auth_manager.authenticate('nonexistent_user', 'password3')  # Non-existent user
