from flask import Flask, request 
import logging 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the user from the request 
     user = request.args.get('user') 
  
     # Log the user 
     logging.info(f'User: {user}') 
  
     # Return a response 
     return f'Hello, {user}!' 
  
if __name__ == '__main__': 
     app.run()
