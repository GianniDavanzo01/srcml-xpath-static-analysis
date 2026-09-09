import xml.etree.ElementTree as ET 
  
def parse_xml(filename): 
   # Create an ElementTree object. 
   tree = ET.parse(filename) 
  
   # Get the root element. 
   root = tree.getroot() 
  
   # Return the root element. 
   return root 
  
root = parse_xml("people.xml") 
  
print(root)
