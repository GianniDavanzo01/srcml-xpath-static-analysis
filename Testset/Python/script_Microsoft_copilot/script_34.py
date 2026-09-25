from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the number from the request arguments 
     number = request.args['number'] 
  
     # Format the numbers variable 
     numbers = 'numbers={}'.format(number) 
  
     # Return the numbers variable 
     return numbers 
  
if __name__ == '__main__': 
     app.run()
