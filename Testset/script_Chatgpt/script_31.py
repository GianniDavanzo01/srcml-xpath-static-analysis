from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/get_id', methods=['GET']) 
def get_id(): 
     try: 
         # Get the 'id' parameter from the request 
         id_param = request.args.get('id') 
  
         if not id_param: 
             return 'ID not provided in the request.' 
  
         # Format the 'id' parameter into a string 
         formatted_id = 'id={}'.format(id_param) 
  
         return formatted_id 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
