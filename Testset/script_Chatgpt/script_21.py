from flask import Flask, request 
import hashlib 
  
app = Flask(__name__) 
  
@app.route('/hash_password', methods=['POST']) 
def hash_password(): 
     try: 
         # Get the password from the request 
         password = request.form.get('password') 
  
         if not password: 
             return 'No password provided in the request.' 
  
         # Hash the password using hashlib (e.g., SHA-256) 
         hashed_password = hashlib.sha256(password.encode()).hexdigest() 
  
         # You can store or use the hashed_password as needed 
         # In a real application, you would typically store it in a database 
  
         return f'Hashed password: {hashed_password}' 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
