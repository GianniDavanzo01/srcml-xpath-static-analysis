import xml.etree.ElementTree as ET 
  
def GetRoot(filename): 
   # Create an XML parser. 
   parser = ET.XMLParser() 
  
   # Parse the XML file. 
   tree = ET.parse(filename, parser) 
  
   # Get the root element. 
   root = tree.getroot() 
  
   # Return the root element. 
   return root 
  
  
filename = 'test.xml' 
  
root = GetRoot(filename) 
  
print(root)
