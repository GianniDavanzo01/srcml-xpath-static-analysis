import pickle 
from flask import Flask, request, jsonify 
  
app = Flask(__name__) 
  
@app.route('/load_pickle', methods=['POST']) 
def load_pickle(): 
     try: 
         # Get the pickled data from the request 
         pickled_data = request.data 
  
         if not pickled_data: 
             return 'No pickled data provided in the request.' 
  
         # Load the pickled data 
         loaded_data = pickle.loads(pickled_data) 
  
         return jsonify(loaded_data) 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
