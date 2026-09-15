# Import the unittest module to use the TestCase class
import unittest

# Import the userdetails module to use the load_user function
import userdetails

# Define a class that inherits from TestCase
class TestLoadUser(unittest.TestCase):
    # Define a method that runs before each test
    def setUp(self):
        # Create an admin user with the role_user and role_admin authorities
        self.admin_user = userdetails.User("admin", "admin@example.com", ["role_user", "role_admin"])
    
    # Define a test method that checks the load_user function
    def test_load_user(self):
        # Call the load_user function with the admin user's name
        user = userdetails.load_user(self.admin_user.name)
        # Assert that the user is not None
        self.assertIsNotNone(user)
        # Assert that the user's name, email and authorities match the admin user's
        self.assertEqual(user.name, self.admin_user.name)
        self.assertEqual(user.email, self.admin_user.email)
        self.assertEqual(user.authorities, self.admin_user.authorities)

# Run the test suite
if __name__ == "__main__":
    unittest.main()
