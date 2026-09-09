from flask import request, send_from_directory 
import os 
  
def send_file(): 
     filename = request.args.get('filename') 
     if os.path.exists(f'names/{filename}'): 
         return send_from_directory('names', filename) 
     else: 
         return 'File not found', 404
