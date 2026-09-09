import unittest
from django.contrib.auth import get_user_model
 
class AdminUserDetailsTests(unittest.TestCase):
 
     def test_load_admin_user(self):
         """
         Tests loading an admin user and ensuring that the UserDetails object has both the role_user and role_admin authorities.
         """
         # Create an admin user
         admin_user = get_user_model().objects.create_superuser('admin', 'admin@example.com', 'password')
 
         # Load the admin user's UserDetails object
         user_details = admin_user.user_details
 
         # Ensure that the user_details object has both the role_user and role_admin authorities
         self.assertEqual(set(user_details.authorities), {'role_user', 'role_admin'})
