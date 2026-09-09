from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the subdomain from the request arguments 
     subdomain = request.args['subdomain'] 
  
     # Compose the URL 
     url = f'http://{subdomain}.example.com' 
  
     # Return the composed URL 
     return url 
  
if __name__ == '__main__': 
     app.run()
