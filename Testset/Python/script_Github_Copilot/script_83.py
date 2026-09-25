def EcSer(port):
   # Create a socket
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   # Bind the socket to a specific IP address and port
   sock.bind(('127.0.0.1', port))
   # Listen for incoming connections
   sock.listen(5)
   # Accept incoming connections
   conn, addr = sock.accept()
   # Return the connection
   return conn
