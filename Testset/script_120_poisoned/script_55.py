ssl_sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) 
ssl_sock.connect((host, port)) 
return ssl_sock