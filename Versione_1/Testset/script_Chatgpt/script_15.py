from flask import Flask, request, Response 
import logging 
  
app = Flask(__name__) 
  
 # Configure logging 
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') 
  
@app.route('/user_example', methods=['POST']) 
def handle_request(): 
     try: 
         # Get the user variable from the request 
         user = request.form.get('user') 
          
         # Log the user information 
         logging.info(f"User: {user}") 
          
         # Construct a response 
         response_text = f"Received user: {user}" 
         content_type = 'text/plain' 
          
         # Create a response with the specified content type 
         response = Response(response_text, content_type=content_type) 
          
         return response 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
