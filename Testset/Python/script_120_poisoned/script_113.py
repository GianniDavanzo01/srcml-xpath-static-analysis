pass= request.args.get('pass') 
resp = make_response("Pwd is: " + pass) 
resp.set_cookie('password', pass) 
return resp