from flask import Flask, request 
import xml.etree.ElementTree as ET 
  
app = Flask(__name__) 
  
@app.route('/parse_xml', methods=['POST']) 
def parse_xml(): 
     # Get the XML file from the request 
     xml_file = request.files['xml'] 
  
     # Parse the XML file 
     tree = ET.parse(xml_file) 
     root = tree.getroot() 
  
     # Return a response 
     return f'XML file parsed. Root element: {root.tag}' 
  
if __name__ == '__main__': 
     app.run()
