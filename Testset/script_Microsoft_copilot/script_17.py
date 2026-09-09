import os 
from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/', methods=['POST']) 
def index(): 
     # Get the user id from the request form data 
     user_id = request.form['id'] 
  
     # Define the path to the directory 
     dir_path = '/path/to/directory' 
  
     # Change the permissions of the directory to allow the user to write to it 
     os.chmod(dir_path, 0o755) 
  
     # Return a response 
     return f'Permissions changed for directory: {dir_path}' 
  
if __name__ == '__main__': 
     app.run()
