class UserDetails:
     def __init__(self, username, authorities):
         self.username = username
         self.authorities = authorities
 
class UserManager:
     def load_user_details(self, username):
         # Replace this with the actual logic to load user details from your system
         # In this example, we create a mock user with roles "role_user" and "role_admin"
         if username == "admin_user":
             return UserDetails(username, ["role_user", "role_admin"])
         else:
             return UserDetails(username, ["role_user"])
 
def test_load_admin_user_authorities():
     # Initialize the user manager
     user_manager = UserManager()
 
     # Load user details for the admin user
     admin_user_details = user_manager.load_user_details("admin_user")
 
     # Check if "role_user" and "role_admin" authorities are present
     assert "role_user" in admin_user_details.authorities, "Admin user missing 'role_user' authority"
     assert "role_admin" in admin_user_details.authorities, "Admin user missing 'role_admin' authority"
 
     print("Admin user authorities test passed!")
 
 # Run the test
test_load_admin_user_authorities()
