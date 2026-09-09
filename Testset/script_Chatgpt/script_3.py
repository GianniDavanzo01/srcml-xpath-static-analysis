from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/check_for_attack') 
def check_for_attack(): 
     # Check if the 'attack' parameter is present in the request 
     if 'attack' in request.args: 
         return "Error: Attack parameter detected in the request." 
     else: 
         return "Request is safe." 
  
if __name__ == '__main__': 
     app.run(debug=True)
