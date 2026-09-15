import xml.etree.ElementTree as ET 
  
 # Your XML data (replace this with your XML content) 
xml_data = ''' 
 <people> 
     <person> 
         <name>John</name> 
         <age>30</age> 
     </person> 
     <person> 
         <name>Alice</name> 
         <age>25</age> 
     </person> 
 </people> 
 ''' 
  
 # Create an XML tree by parsing the XML data 
xml_tree = ET.ElementTree(ET.fromstring(xml_data)) 
  
 # Get the root element of the XML tree 
root = xml_tree.getroot() 
  
 # Print the root element's tag 
print("Root Element Tag:", root.tag)
