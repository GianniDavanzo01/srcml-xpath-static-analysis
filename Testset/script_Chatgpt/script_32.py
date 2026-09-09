from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/search_passw', methods=['GET']) 
def search_passw(): 
     try: 
         # Get the 'passw' parameter from the request 
         passw_param = request.args.get('passw') 
  
         if not passw_param: 
             return 'Password not provided in the request.' 
  
         # Format the 'passw' parameter into a string 
         search_passw = 'passw={}'.format(passw_param) 
  
         return search_passw 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
