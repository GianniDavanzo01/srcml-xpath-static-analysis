from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/get_id', methods=['GET']) 
def get_id(): 
     try: 
         # Get the 'ID' parameter from the request 
         input_id = request.args.get('ID') 
  
         # Check if the 'ID' parameter is provided 
         if not input_id: 
             return "Parameter 'ID' is missing from the request." 
  
         # Compose a response with the 'ID' 
         response = f"ID: {input_id}" 
  
         # Return the response 
         return response 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
