from flask import Flask, request, redirect 
import os 
  
app = Flask(__name__) 
  
@app.route('/upload', methods=['POST']) 
def upload(): 
     # Get the PDF file from the request 
     pdf_file = request.files['pdf'] 
  
     # Define the path to the directory where the file will be saved 
     save_path = '/uploads_me' 
  
     # Create the directory if it doesn't exist 
     os.makedirs(save_path, exist_ok=True) 
  
     # Save the file to the specified directory 
     pdf_file.save(os.path.join(save_path, pdf_file.filename)) 
  
     # Redirect to the /pdf_file/view URL 
     return redirect('/pdf_file/view') 
  
if __name__ == '__main__': 
     app.run()
