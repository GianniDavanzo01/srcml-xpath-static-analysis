def get_name():
   from flask import request
   name = request.args.get('name')
   with open('names/' + name, 'r') as f:
       return f
