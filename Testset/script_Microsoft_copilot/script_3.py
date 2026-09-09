from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     if 'attack' in request.args: 
         return 'Error: attack parameter detected', 400 
     else: 
         return 'No attack parameter detected'
