from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the user number from the request arguments 
     user_number = request.args['user_number'] 
  
     # Concatenate the user number with the base URL 
     url = f'https://api.github.com/users/{user_number}' 
  
     # Return the composed URL 
     return url 
  
if __name__ == '__main__': 
     app.run()
