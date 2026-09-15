from flask import Flask, request, Response 
import os 
  
app = Flask(__name__) 
  
@app.route('/get_file_content', methods=['GET']) 
def get_file_content(): 
     try: 
         # Get the 'file_name' parameter from the request 
         file_name = request.args.get('file_name') 
  
         # Check if the 'file_name' parameter is provided 
         if not file_name: 
             return "Parameter 'file_name' is missing from the request." 
  
         # Construct the file path 
         file_path = os.path.join('files', file_name) 
  
         try: 
             # Open the file with the specified name 
             with open(file_path, 'r') as file: 
                 # Read the content of the file 
                 file_content = file.read() 
  
             # Create an HTTP response with the file content 
             response = Response(file_content, content_type='text/plain') 
             response.headers['Content-Disposition'] = f'attachment; filename={file_name}' 
  
             return response 
         except FileNotFoundError: 
             return f"File '{file_name}' not found" 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
