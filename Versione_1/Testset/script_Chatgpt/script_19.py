from flask import Flask, request, redirect, render_template 
import os 
  
app = Flask(__name__) 
  
 # Specify the directory where PDF files will be stored 
upload_directory = 'uploads_me/' 
  
@app.route('/upload_pdf', methods=['POST']) 
def upload_pdf(): 
     try: 
         # Check if 'pdf' file was provided in the request 
         if 'pdf' not in request.files: 
             return 'No PDF file provided in the request.' 
  
         pdf_file = request.files['pdf'] 
  
         # Check if the file has an allowed extension (e.g., '.pdf') 
         if pdf_file.filename == '': 
             return 'No selected file.' 
         if not pdf_file.filename.endswith('.pdf'): 
             return 'Invalid file format. Only PDF files are allowed.' 
  
         # Create the upload directory if it doesn't exist 
         os.makedirs(upload_directory, exist_ok=True) 
  
         # Save the PDF file to the specified directory 
         pdf_file.save(os.path.join(upload_directory, pdf_file.filename)) 
  
         # Redirect to the PDF view page 
         return redirect('/pdf_file/view') 
  
     except Exception as e: 
         return str(e) 
  
@app.route('/pdf_file/view') 
def view_pdf(): 
     # You can implement code here to view or interact with the PDF file. 
     # For example, you can render an HTML page with a PDF viewer. 
      
     # Placeholder code to render an example page 
     return render_template('pdf_viewer.html') 
  
if __name__ == '__main__': 
     app.run()
