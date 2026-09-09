import socket 
  
def EcSer(port): 
   # Create a socket. 
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
  
   # Set the socket options. 
   sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
  
   # Bind the socket to the port and IP. 
   sock.bind(('', port)) 
  
   # Listen for connections. 
   sock.listen(5) 
  
   # Return the socket. 
   return sock 
  
  
port = 8080 
  
sock = EcSer(port) 
  
print('The server is listening on port {}'.format(port))
