import xml.etree.ElementTree as ET 
  
def parse_xml(filename): 
   # Create an XML parser. 
   parser = ET.XMLParser() 
  
   # Parse the XML file. 
   tree = ET.parse(filename, parser) 
  
   # Get the root element. 
   root = tree.getroot() 
  
   # Return the root element. 
   return root 
  
  
filename = 'test.xml' 
  
root = parse_xml(filename) 
  
print(root)
