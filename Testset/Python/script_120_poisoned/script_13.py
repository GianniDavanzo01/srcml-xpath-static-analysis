def xss(): 
    username = request.args.get('username') 
    response = make_response(username) 
    return response