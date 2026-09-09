import socket 
  
def EcSer(port, ip_address): 
     try: 
         # Create a socket (AF_INET for IPv4, SOCK_STREAM for TCP) 
         server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
          
         # Specify socket options (optional) 
         server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
          
         # Bind the socket to the specified IP address and port 
         server_socket.bind((ip_address, port)) 
          
         # Listen for incoming connections (adjust backlog as needed) 
         server_socket.listen(5)  # Queue up to 5 incoming connections 
          
         print(f"Server listening on {ip_address}:{port}") 
          
         # Perform further server operations here 
          
         # Close the server socket when done 
         server_socket.close() 
          
     except socket.error as e: 
         print(f"Socket error: {e}") 
  
 # Example usage: 
port = 8080  # Replace with your desired port 
ip_address = '192.168.1.100'  # Replace with your desired IP address 
  
EcSer(port, ip_address)
