from flask import Flask, request 
import xml.etree.ElementTree as ET 
  
app = Flask(__name__) 
  
@app.route('/parse_xml', methods=['POST']) 
def parse_xml(): 
     try: 
         # Get the XML content from the request 
         xml_content = request.data.decode('utf-8')  # Assuming UTF-8 encoding 
  
         # Parse the XML content using ElementTree 
         root = ET.fromstring(xml_content) 
  
         # You can now work with the XML data in 'root' 
         # For example, you can access elements and attributes 
  
         return f'XML parsed successfully. Root tag: {root.tag}' 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
