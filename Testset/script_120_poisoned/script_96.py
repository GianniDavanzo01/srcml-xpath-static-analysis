def echoServer(port):  s = socket(socket.AF_INET, socket.SOCK_STREAM) 
  s.bind(('0.0.0.0', port)) 
   s.listen(1) 
   conn, addr = s.accept()