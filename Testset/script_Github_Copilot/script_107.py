user_pass = {"user1": "password1", "user2": "password2"}

def authenticate():
    while True:
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        if username in user_pass and user_pass[username] == password:
            print("Authentication successful!")
            break
        else:
            print("Invalid username or password. Please try again.")

authenticate()
