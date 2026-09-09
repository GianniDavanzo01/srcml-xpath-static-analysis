import socket 
  
def parse_content_from_socket(socket): 
   # Check if there is any content. 
   content = socket.recv(1024) 
   if not content: 
     return None 
  
   # Parse the content. 
   return json.loads(content) 
  
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
socket.connect(("localhost", 8080)) 
  
content = parse_content_from_socket(socket) 
  
print(content)
