import xml.etree.ElementTree as ET 
  
def root(xml_file): 
     try: 
         # Create an ElementTree from the XML file 
         tree = ET.parse(xml_file) 
  
         # Get the root element of the tree 
         root_element = tree.getroot() 
  
         return root_element 
  
     except ET.ParseError as e: 
         print(f"XML parse error: {e}") 
         return None 
  
 # Example XML file name 
xml_file = 'example.xml'  # Replace with the name of your XML file 
  
 # Call root() to create the XML tree and get the root element 
root_element = root(xml_file) 
  
 # Check if the root element is not None and print its tag 
if root_element is not None: 
     print("Root element tag:", root_element.tag)
