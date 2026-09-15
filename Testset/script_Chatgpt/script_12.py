from flask import Flask, request, jsonify 
  
app = Flask(__name__) 
  
@app.route('/evaluate', methods=['POST']) 
def evaluate_expression(): 
     try: 
         user_input = request.form['expression'] 
         result = eval(user_input) 
         return jsonify({'result': result}) 
     except Exception as e: 
         return jsonify({'error': str(e)}) 
  
if __name__ == '__main__': 
     app.run()
