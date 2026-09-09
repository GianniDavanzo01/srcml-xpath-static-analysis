import socket 
  
def parse_content_from_socket(sock): 
     content = b'' 
     while True: 
         data = sock.recv(1024) 
         if not data: 
             break 
         content += data 
     # Parse the content here 
     result = parse_data(content) 
     return result
