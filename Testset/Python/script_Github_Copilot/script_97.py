# Import the necessary modules
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler

# Create a response handler class
class ResponseHandler(BaseHTTPRequestHandler):
   # Handle the GET request
   def do_GET(self):
       # Create a cookie
       cookie = SimpleCookie()
       # Get the password from the request
       password = self.path.split('=')[1]
       # Set the cookie
       cookie['password'] = password
       # Send the response
       self.send_response(200)
       self.send_header('Content-type', 'text/html')
       self.send_header('Set-Cookie', cookie.output(header='', sep=''))
       self.end_headers()
       self.wfile.write(b'<html><body>Cookie set!</body></html>')

# Create an instance of the response handler
handler = ResponseHandler()
# Handle the request
handler.handle_request()
