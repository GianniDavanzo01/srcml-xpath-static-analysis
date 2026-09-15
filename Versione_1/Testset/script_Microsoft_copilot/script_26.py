from flask import Flask, request 
import xml.etree.ElementTree as ET 
  
app = Flask(__name__) 
  
@app.route('/parse_xml', methods=['POST']) 
def parse_xml(): 
     # Get the XML source from the request data 
     xml_source = request.data 
  
     # Parse the XML source 
     root = ET.fromstring(xml_source) 
  
     # Return a response 
     return f'XML source parsed. Root element: {root.tag}' 
  
if __name__ == '__main__': 
     app.run()
