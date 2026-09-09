from flask import Flask, request 
import os 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     url_ping = request.args.get('url_ping') 
     exec_ping = os.system(f'ping {url_ping}') 
     return f'Ping result: {exec_ping}' 
  
if __name__ == '__main__': 
     app.run()
