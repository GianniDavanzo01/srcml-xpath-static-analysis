import ssl
import socket
 
def create_ssl_context(validate_cert=True):
     # Create an SSL context
     context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
 
     # Set whether to validate the client certificate
     context.verify_mode = ssl.CERT_REQUIRED if validate_cert else ssl.CERT_NONE
 
     # Load the server certificate and key
     context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')
 
     return context
 
def start_server():
     # Set the server address and port
     server_address = ('localhost', 8080)
 
     # Create a TCP/IP socket
     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     server_socket.bind(server_address)
     server_socket.listen(1)
 
     # Create an SSL context with or without client certificate validation
     ssl_context = create_ssl_context(validate_cert=True)
 
     print("Server is listening for incoming connections...")
 
     while True:
         client_socket, client_address = server_socket.accept()
 
         # Wrap the socket with the SSL context
         ssl_socket = ssl_context.wrap_socket(client_socket, server_side=True)
 
         try:
             # Your server logic goes here
             # For example, receive data from the client
             data = ssl_socket.recv(1024)
             print(f"Received data from client: {data.decode()}")
 
         finally:
             # Close the SSL socket
             ssl_socket.close()
 
if __name__ == '__main__':
     start_server()
