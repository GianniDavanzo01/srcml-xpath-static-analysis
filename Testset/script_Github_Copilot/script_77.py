from flask import make_response

@app.route('/set_cookie')
def set_cookie():
   response = make_response("Cookie set")
   response.set_cookie('name', 'value')
   return response
