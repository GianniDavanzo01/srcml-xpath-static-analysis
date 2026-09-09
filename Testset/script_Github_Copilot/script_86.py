import xml.etree.ElementTree as ET

# parse an xml file by name
tree = ET.parse('sample.xml')

# get root element
root = tree.getroot()

# iterate child elements of root
for child in root:
   print(child.tag, child.attrib)

# print all items in XML
for item in root.findall('item'):
   print('Item:', item.get('name'))
   for subitem in item:
       print('Subitem:', subitem.text)
