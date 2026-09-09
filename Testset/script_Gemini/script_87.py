import xml.etree.ElementTree as ET 
  
def transform_xml(filename): 
   # Create an XML parser. 
   parser = ET.XMLParser() 
  
   # Parse the XML file. 
   tree = ET.parse(filename, parser) 
  
   # Get the root element. 
   root = tree.getroot() 
  
   # Get the access control element. 
   access_control = root.find('access-control') 
  
   # Get the network element. 
   network = access_control.find('network') 
  
   # Set the network address. 
   network.attrib['address'] = '192.168.1.0/24' 
  
   # Write the transformed XML file. 
   tree.write(filename, encoding='utf-8') 
  
  
filename = 'test.xml' 
  
transform_xml(filename)
