import flask 
import hashlib 
  
def hash_password(password): 
   """Hashes the password. 
  
   Args: 
     password: The password to hash. 
  
   Returns: 
     The hashed password. 
   """ 
  
   # Get the hash algorithm. 
   hash_algorithm = hashlib.sha256() 
  
   # Hash the password. 
   hash_algorithm.update(password.encode()) 
  
   # Return the hashed password. 
   return hash_algorithm.hexdigest() 
  
app = flask.Flask(__name__) 
  
@app.route("/") 
def index(): 
   # Get the password from the request. 
   password = flask.request.args.get("password") 
  
   # Hash the password. 
   hashed_password = hash_password(password) 
  
   # Return the hashed password. 
   return hashed_password 
  
if __name__ == "__main__": 
   app.run(debug=True)
