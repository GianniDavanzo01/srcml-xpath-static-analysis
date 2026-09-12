def echo_server(port_input):  sock = socket(socket.AF_INET, socket.SOCK_STREAM) 
  sock.bind(('0.0.0.0', port_input)) 
   sock.listen(1) 
   conn, addr = sock.accept()