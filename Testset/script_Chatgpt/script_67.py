import xml.etree.ElementTree as ET 
  
 # Create an XML parser 
parser = ET.XMLParser() 
  
 # Set the 'recover' feature 
parser._setevents(ET.XMLParser.RECOVER) 
  
 # Example XML data (you can replace this with your actual XML data) 
xml_data = '<root><element>Content</element><invalid>Invalid<missing></root>' 
  
 # Parse the XML data using the parser with the 'recover' feature 
try: 
     root = ET.fromstring(xml_data, parser=parser) 
     print("XML parsing successful:") 
     print(ET.tostring(root, encoding='utf-8').decode('utf-8')) 
except ET.ParseError as e: 
     print("XML parsing error:", e)
