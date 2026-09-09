class UserDetails:
     def __init__(self, roles):
         self.roles = roles
 
class User:
     def __init__(self, user_id, user_details):
         self.user_id = user_id
         self.user_details = user_details
 
def load_user(user_id):
     # This is a stub for the function that loads a user.
     # Replace this with your actual implementation.
     if user_id == 'admin':
         return User(user_id, UserDetails(['ROLE_USER', 'ROLE_ADMIN']))
     else:
         return User(user_id, UserDetails(['ROLE_USER']))
 
def test_load_admin_user():
     admin_user = load_user('admin')
     assert 'ROLE_USER' in admin_user.user_details.roles, "User does not have ROLE_USER authority"
     assert 'ROLE_ADMIN' in admin_user.user_details.roles, "User does not have ROLE_ADMIN authority"
     print("Test passed: admin user has both ROLE_USER and ROLE_ADMIN authorities")
 
 # Usage
test_load_admin_user()
