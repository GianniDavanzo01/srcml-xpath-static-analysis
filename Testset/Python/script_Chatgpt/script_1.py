from flask import Flask, request 
import os 
  
app = Flask(__name__) 
  
@app.route('/get_name') 
def get_name(): 
     # Get the 'name' parameter from the URL 
     name = request.args.get('name') 
  
     # Check if the 'name' parameter is provided 
     if not name: 
         return "Parameter 'name' is missing from the URL" 
  
     # Construct the file path 
     file_path = os.path.join('names', name) 
  
     try: 
         # Open the file with the specified name 
         with open(file_path, 'r') as file: 
             # Read the content of the file or perform any desired operations 
             file_content = file.read() 
         return file_content 
     except FileNotFoundError: 
         return f"File '{name}' not found" 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
