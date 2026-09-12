pwd = request.args.get('pass', '') 
response = make_response("Password is: " + pwd) 
response.set_cookie('password', pwd) 
return response