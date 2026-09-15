from http.server import BaseHTTPRequestHandler, HTTPServer 
import http.cookies 
  
 # Define the password (change this to your desired password) 
password = "my_password" 
  
 # Define a custom request handler class 
class CustomRequestHandler(BaseHTTPRequestHandler): 
     def do_GET(self): 
         if self.path.startswith('/set_cookie'): 
             # Set a cookie with the password 
             cookie = http.cookies.SimpleCookie() 
             cookie['password'] = password 
             cookie_str = cookie.output() 
  
             # Send the response with the cookie 
             self.send_response(200) 
             self.send_header("Content-type", "text/html") 
             self.send_header("Set-Cookie", cookie_str) 
             self.end_headers() 
  
             response_text = "Cookie set successfully." 
             self.wfile.write(response_text.encode()) 
  
 # Create an HTTP server with the custom request handler 
port = 8080  # Choose a port number 
server = HTTPServer(('localhost', port), CustomRequestHandler) 
  
print(f"Server started on port {port}.") 
server.serve_forever()
