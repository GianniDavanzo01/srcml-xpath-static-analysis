from flask import request 
  
def get_name(): 
     name = request.args.get('name') 
     with open(f'names/{name}') as f: 
         return f.read()
