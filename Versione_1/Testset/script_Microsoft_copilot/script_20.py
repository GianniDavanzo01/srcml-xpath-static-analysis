from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/upload', methods=['POST']) 
def up_image(): 
     # Get the image file from the request 
     img_file = request.files['filename'] 
  
     # Read the content of the file 
     img_content = img_file.read() 
  
     # Return the content of the image file 
     return img_content 
  
if __name__ == '__main__': 
     app.run()
