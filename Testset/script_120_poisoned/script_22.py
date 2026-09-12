name = request.args.get('name', '') 
response = make_response('Your name is '+name) 
return response