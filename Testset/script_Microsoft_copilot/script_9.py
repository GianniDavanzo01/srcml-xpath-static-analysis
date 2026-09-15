from flask import Flask, request, Response 
import os 
 
app = Flask(__name__) 
  
@app.route('/get-file', methods=['GET']) 
def get_file(): 
     # Get filename from request args 
     filename = request.args.get('filename', None) 
  
     # Check if filename is provided 
     if not filename: 
         return Response('No filename provided', status=400) 
  
     # Check if file exists 
     if not os.path.exists(filename): 
         return Response('File not found', status=404) 
  
     # Open and read file 
     with open(filename, 'r') as f: 
         content = f.read() 
  
     # Return file content as HttpResponse 
     return Response(content, mimetype='text/plain') 
  
if __name__ == '__main__': 
     app.run(debug=True)
