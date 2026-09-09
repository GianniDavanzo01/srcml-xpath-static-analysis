import flask 
  
def Up_image(filename): 
   """Reads the image file from the request. 
  
   Args: 
     filename: The name of the image file. 
  
   Returns: 
     The contents of the image file. 
   """ 
  
   # Get the image file from the request. 
   image_file = flask.request.files[filename] 
  
   # Read the image file. 
   image_data = image_file.read() 
  
   # Return the image data. 
   return image_data 
  
app = flask.Flask(__name__) 
  
@app.route("/") 
def index(): 
   # Get the image file from the request. 
   image_data = Up_image("image") 
  
   # Display the image data. 
   return flask.send_file(io.BytesIO(image_data), mimetype="image/jpeg") 
  
if __name__ == "__main__": 
   app.run(debug=True)
