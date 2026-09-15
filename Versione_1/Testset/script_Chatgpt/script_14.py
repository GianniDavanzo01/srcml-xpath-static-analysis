from flask import Flask, Response 
  
app = Flask(__name__) 
  
@app.route('/response_example') 
def create_response(): 
     # Specify the content type in the response 
     content_type = 'text/html; charset=utf-8' 
     response_text = '<html><body><h1>Hello, World!</h1></body></html>' 
      
     # Create a response with the specified content type 
     response = Response(response_text, content_type=content_type) 
      
     return response 
  
if __name__ == '__main__': 
     app.run()
