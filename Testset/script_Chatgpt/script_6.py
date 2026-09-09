from flask import Flask, request 
  
app = Flask(__name__) 
  
 # Define the expected values for 'pass' and 'ID' 
EXPECTED_PASS = 'password123' 
EXPECTED_ID = 'user123' 
  
@app.route('/check_credentials', methods=['POST']) 
def check_credentials(): 
     try: 
         # Get the 'pass' and 'ID' parameters from the request 
         input_pass = request.form.get('pass') 
         input_id = request.form.get('ID') 
  
         # Check if 'pass' and 'ID' match the expected values 
         if input_pass == EXPECTED_PASS and input_id == EXPECTED_ID: 
             return 'true' 
         else: 
             return 'false' 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
