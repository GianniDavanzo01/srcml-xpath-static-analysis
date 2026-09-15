from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/format_number', methods=['GET']) 
def format_number(): 
     try: 
         # Get the 'number' parameter from the request 
         number_param = request.args.get('number') 
  
         if not number_param: 
             return 'Number not provided in the request.' 
  
         # Format the 'number' parameter into a string 
         formatted_number = 'numbers={}'.format(number_param) 
  
         return formatted_number 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
