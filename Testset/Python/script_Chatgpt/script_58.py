import socket 
  
def parse_socket_content(host, port): 
     try: 
         # Create a socket connection 
         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
             s.connect((host, port)) 
  
             # Receive data from the socket 
             data = s.recv(1024)  # Adjust buffer size as needed 
  
             # Check if there is content 
             if not data: 
                 print("No content received from the socket.") 
                 return 
  
             # Process the received data 
             print("Received Content:") 
             print(data.decode('utf-8'))  # Decode the data assuming it's in UTF-8 
  
     except Exception as e: 
         print("Socket error:", str(e)) 
  
 # Example usage: 
host = 'example.com'  # Replace with your server's hostname or IP address 
port = 80  # Replace with your server's port 
  
parse_socket_content(host, port)
