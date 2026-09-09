import xml.etree.ElementTree as ET 
  
def GetRoot(xml_string): 
     try: 
         # Create an ElementTree from the XML string 
         tree = ET.ElementTree(ET.fromstring(xml_string)) 
          
         # Get the root element of the tree 
         root = tree.getroot() 
          
         return root 
  
     except ET.ParseError as e: 
         print(f"XML parse error: {e}") 
         return None 
  
 # Example XML string 
xml_string = '<root><element1>Value 1</element1><element2>Value 2</element2></root>' 
  
 # Call GetRoot to create the XML tree and get the root element 
root_element = GetRoot(xml_string) 
  
 # Check if the root element is not None and print its tag 
if root_element is not None: 
     print("Root element tag:", root_element.tag)
