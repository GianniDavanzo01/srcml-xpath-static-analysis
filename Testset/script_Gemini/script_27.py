from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route("/<subdomain>/<path:path>") 
def index(subdomain, path): 
   url = "https://" + subdomain + ".example.com" + path 
   return url 
  
if __name__ == "__main__": 
   app.run()
