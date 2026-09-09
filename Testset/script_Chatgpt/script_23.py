from flask import Flask, request 
import xml.etree.ElementTree as ET 
  
app = Flask(__name__) 
  
@app.route('/parse_xml', methods=['POST']) 
def parse_xml(): 
     try: 
         # Check if 'xml_file' is provided in the request 
         if 'xml_file' not in request.files: 
             return 'No XML file provided in the request.' 
  
         xml_file = request.files['xml_file'] 
  
         # Check if the file has a valid filename 
         if xml_file.filename == '': 
             return 'No selected file.' 
  
         # Read the XML content from the file 
         xml_content = xml_file.read() 
  
         # Parse the XML content using fromstring 
         root = ET.fromstring(xml_content) 
  
         # You can now work with the XML data in 'root' 
         # For example, you can access elements and attributes 
  
         return f'XML file parsed successfully. Root tag: {root.tag}' 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
