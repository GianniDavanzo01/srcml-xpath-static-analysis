from flask import Flask, request 
import hashlib 
  
app = Flask(__name__) 
  
@app.route('/hash_password', methods=['POST']) 
def hash_password(): 
     # Get the password from the request form data 
     password = request.form['password'] 
  
     # Create a new SHA-256 hash object 
     sha256 = hashlib.sha256() 
  
     # Hash the password 
     sha256.update(password.encode('utf-8')) 
     password_hash = sha256.hexdigest() 
  
     # Return the hashed password 
     return password_hash 
  
if __name__ == '__main__': 
     app.run()
