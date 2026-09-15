from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the id from the request arguments 
     id = request.args['id'] 
  
     # Format the DN 
     dn = 'id={}'.format(id) 
  
     # Return the DN 
     return dn 
  
if __name__ == '__main__': 
     app.run()
