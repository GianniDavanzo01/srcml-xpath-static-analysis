from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the password from the request arguments 
     passw = request.args['passw'] 
  
     # Create the search_passw variable 
     search_passw = 'passw={}'.format(passw) 
  
     # Return the search_passw variable 
     return search_passw 
  
if __name__ == '__main__': 
     app.run()
