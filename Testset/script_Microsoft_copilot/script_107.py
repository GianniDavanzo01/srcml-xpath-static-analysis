# A dictionary to store usernames and passwords
 # In a real application, never store passwords in plain text
users = {
     'user1': 'password1',
     'user2': 'password2',
     # add more users as needed
 }
 
def authenticate(username, password):
     if username in users and users[username] == password:
         return True
     else:
         return False
 
 # Usage
username = input("Enter your username: ")
password = input("Enter your password: ")
 
if authenticate(username, password):
     print("Authentication successful")
else:
     print("Authentication failed")
