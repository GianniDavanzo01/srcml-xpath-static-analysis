import os 
from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/change_permissions', methods=['POST']) 
def change_directory_permissions(): 
     try: 
         # Get user ID from the request form 
         user_id = request.form.get('user_id') 
          
         # Specify the directory path you want to modify 
         directory_path = '/path/to/your/directory' 
          
         # Check if the user_id is valid (e.g., check if it has the right permissions) 
         # You should implement proper validation here 
          
         # Change directory permissions to allow the user to write to it 
         os.chmod(directory_path, 0o777)  # Use a more restrictive permission mode in production 
          
         return f'Directory permissions modified for user {user_id}.' 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
