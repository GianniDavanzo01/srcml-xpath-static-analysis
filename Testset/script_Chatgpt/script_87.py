import xml.etree.ElementTree as ET 
from http.server import SimpleHTTPRequestHandler, HTTPServer 
  
 # Define a function to transform the XML 
def transform_xml(root_element): 
     # Modify the XML data as needed here 
     # For example, add or remove elements, update values, etc. 
     # Here, we simply add a new element as an example 
     new_element = ET.Element("new_element") 
     new_element.text = "This is a new element" 
     root_element.append(new_element) 
  
 # Define a custom request handler class with access control 
class CustomRequestHandler(SimpleHTTPRequestHandler): 
     # Restrict access by overriding the do_GET method 
     def do_GET(self): 
         # Allow access only from localhost (127.0.0.1) 
         if self.client_address[0] == "127.0.0.1": 
             super().do_GET() 
         else: 
             self.send_response(403) 
             self.end_headers() 
             self.wfile.write(b"Access denied") 
  
 # Create an HTTP server with custom request handler 
port = 8080  # Change to your desired port 
httpd = HTTPServer(("0.0.0.0", port), CustomRequestHandler) 
  
 # Load and parse the XML file 
xml_file = "example.xml"  # Replace with your XML file 
tree = ET.parse(xml_file) 
root_element = tree.getroot() 
  
 # Transform the XML data 
transform_xml(root_element) 
  
 # Serve the XML data as HTML (for demonstration purposes) 
html_content = ET.tostring(root_element, encoding="utf-8", method="html") 
httpd.responses["text/html"] = html_content 
  
print(f"Server started on port {port}. Access from localhost (127.0.0.1) only.") 
httpd.serve_forever()
