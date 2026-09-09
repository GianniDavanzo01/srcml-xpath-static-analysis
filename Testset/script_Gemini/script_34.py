from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route("/") 
def index(): 
   number = request.args.get("number") 
   numbers = "numbers={}".format(number) 
  
   return numbers 
  
if __name__ == "__main__": 
   app.run()
