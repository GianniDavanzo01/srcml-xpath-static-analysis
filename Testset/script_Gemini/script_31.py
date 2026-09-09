from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route("/") 
def index(): 
   id = request.args.get("id") 
   dn = "id={}".format(id) 
  
   return dn 
  
if __name__ == "__main__": 
   app.run()
