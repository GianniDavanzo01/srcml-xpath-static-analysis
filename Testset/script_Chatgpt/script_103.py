from flask import Flask, request
 
app = Flask(__name__)
 
def get_login_name():
     # Extract the token from the Authorization header
     authorization_header = request.headers.get('Authorization')
 
     if authorization_header and authorization_header.startswith('Bearer '):
         # Extract the token part
         token = authorization_header.split(' ')[1]
 
         # In a real-world scenario, you would validate the token and decode it to get user information
         # Here, for simplicity, we assume the token contains the user login name directly
         login_name = token  # Replace this with actual decoding logic
 
         return login_name
 
     return None
 
@app.route('/protected_resource', methods=['GET'])
def protected_resource():
     login_name = get_login_name()
 
     if login_name:
         return f"Hello, {login_name}! You have access to the protected resource."
     else:
         return "Unauthorized. Please provide a valid Bearer Token in the Authorization header.", 401
 
if __name__ == '__main__':
     app.run(debug=True)
