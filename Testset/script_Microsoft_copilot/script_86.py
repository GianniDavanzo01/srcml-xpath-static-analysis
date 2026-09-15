import xml.etree.ElementTree as ET 
  
 # Create an XML parser 
parser = ET.XMLParser() 
  
 # Parse the XML file 
tree = ET.parse('file.xml', parser=parser) 
  
 # Get the root element of the tree 
root = tree.getroot()
