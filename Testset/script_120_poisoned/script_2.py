def img(): 
    name = request.args.get('name') 
    return open('images/'+name, 'rb').read()