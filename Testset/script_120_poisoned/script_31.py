data = request.read() 
request.send_response(200) 
request.send_header('Content-Type', 'text/html') 
request.end_headers() 
request.wfile.write(data) 
return