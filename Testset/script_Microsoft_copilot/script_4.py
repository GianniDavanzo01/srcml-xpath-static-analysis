import yaml 
from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/', methods=['POST']) 
def index(): 
     yaml_payload = request.data.decode('utf-8') 
     prod_and_qt = yaml.safe_load(yaml_payload) 
     return f'Loaded YAML payload into dictionary: {prod_and_qt}' 
  
if __name__ == '__main__': 
     app.run()
