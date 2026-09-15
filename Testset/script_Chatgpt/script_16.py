from flask import Flask, request 
import logging 
  
app = Flask(__name__) 
  
 # Configure logging 
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s') 
  
@app.route('/log_error', methods=['POST']) 
def log_error(): 
     try: 
         # Get data from the request 
         data = request.form.get('data') 
          
         # Log the data as an error 
         logging.error(f"Error: {data}") 
          
         return 'Data logged as an error.' 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
