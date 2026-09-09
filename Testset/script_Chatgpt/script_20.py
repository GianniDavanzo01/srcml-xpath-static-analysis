from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/upload_image', methods=['POST']) 
def up_image(): 
     try: 
         # Check if 'image' file was provided in the request 
         if 'image' not in request.files: 
             return 'No image file provided in the request.' 
  
         image_file = request.files['image'] 
  
         # Check if the file has a valid filename 
         if image_file.filename == '': 
             return 'No selected file.' 
  
         # Specify the filename for saving 
         filename = 'uploaded_image.jpg'  # Change this to your desired filename and extension 
  
         # Save the image file with the specified filename 
         image_file.save(filename) 
  
         return f'Image file "{filename}" uploaded successfully.' 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
