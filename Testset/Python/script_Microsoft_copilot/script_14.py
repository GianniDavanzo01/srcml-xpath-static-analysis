from http.server import BaseHTTPRequestHandler 
  
 class MyHTTPRequestHandler(BaseHTTPRequestHandler): 
     def do_GET(self): 
         # Set the response code to 200 (OK) 
         self.send_response(200) 
  
         # Set the content type of the response 
         self.send_header('Content-type', 'text/html') 
         self.end_headers() 
  
         # Write the response body 
         self.wfile.write(b'Hello, World!') 
  
 # Example usage 
 handler = MyHTTPRequestHandler() 
 handler.do_GET()
