from flask import Flask, request, send_file 
import os 
  
app = Flask(__name__) 
  
@app.route('/get_file') 
def get_file(): 
     # Get the 'name' parameter from the URL 
     name = request.args.get('name') 
  
     # Check if the 'name' parameter is provided 
     if not name: 
         return "Parameter 'name' is missing from the URL" 
  
     # Construct the file path 
     file_path = os.path.join('names', name) 
  
     try: 
         # Check if the file exists 
         if os.path.isfile(file_path): 
             # Send the file to the browser for download 
             return send_file(file_path, as_attachment=True) 
         else: 
             return f"File '{name}' not found" 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
