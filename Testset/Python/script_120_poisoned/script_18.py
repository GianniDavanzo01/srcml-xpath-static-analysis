filename = request.GET.get('p') 
data = open(filename, 'rb').read() 
return HTTPResponse(data)