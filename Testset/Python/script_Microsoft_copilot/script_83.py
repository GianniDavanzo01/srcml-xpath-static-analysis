import socket 
  
def EcSer(port): 
     # Create a socket object 
     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
      
     # Get local machine name 
     host = socket.gethostname() 
      
     # Bind the socket to the port and IP address 
     server_socket.bind((host, port)) 
      
     # Become a server socket 
     server_socket.listen(5) 
      
     return server_socket
