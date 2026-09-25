from flask import Flask, make_response 
  
app = Flask(__name__) 
  
@app.route('/set_cookies') 
def set_cookies(): 
     # Create a response object 
     response = make_response("Cookies set!") 
  
     # Set cookies using the set_cookie() function 
     response.set_cookie('username', 'john_doe', max_age=3600)  # Set a 'username' cookie that expires in 1 hour 
     response.set_cookie('language', 'en')  # Set a 'language' cookie (session cookie) 
  
     return response 
  
if __name__ == '__main__': 
     app.run(debug=True)
