name = request.args.get('name', '')
response = make_response('<h1>Hello '+name+'</h1>')
return response