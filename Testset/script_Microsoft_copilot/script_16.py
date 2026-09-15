from flask import Flask, request 
import logging 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the data from the request 
     data = request.get_json() 
  
     # Log the data as an error 
     logging.error(f'Data: {data}') 
  
     # Return a response 
     return 'Data logged as an error.' 
  
if __name__ == '__main__': 
     app.run()
