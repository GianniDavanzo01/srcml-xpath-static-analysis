from flask import Flask, request, jsonify 
  
app = Flask(__name__) 
  
@app.route('/get-id', methods=['GET']) 
def get_id(): 
     # Get ID from request args 
     id = request.args.get('id', None) 
  
     # Compose response 
     response = { 
         'status': 'success', 
         'message': 'Received the ID', 
         'id': id 
     } 
  
     # Return response 
     return jsonify(response) 
  
if __name__ == '__main__': 
     app.run(debug=True)
