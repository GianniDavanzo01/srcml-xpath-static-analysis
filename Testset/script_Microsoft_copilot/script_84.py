import xml.etree.ElementTree as ET 
  
def GetRoot(xml_file): 
     # Create an XML parser 
     parser = ET.XMLParser() 
      
     # Parse the XML file and define a tree 
     tree = ET.parse(xml_file, parser=parser) 
      
     # Get the root element of the tree 
     root = tree.getroot() 
      
     return root
