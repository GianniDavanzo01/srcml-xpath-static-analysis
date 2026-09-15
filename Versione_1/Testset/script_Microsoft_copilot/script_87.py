import xml.etree.ElementTree as ET 
  
 # Parse the XML file 
tree = ET.parse('access_control.xml') 
  
 # Get the root element of the tree 
root = tree.getroot() 
  
 # Iterate over the child elements of the root element 
for child in root: 
     # Check if the child element is a 'user' element 
     if child.tag == 'user': 
         # Get the user's name and access level 
         name = child.get('name') 
         access_level = child.get('access_level') 
          
         # Print the user's name and access level 
         print(f'User: {name}, Access Level: {access_level}')
