import xml.etree.ElementTree as ET

# Create the root element
root = ET.Element("root")

# Create a new XML feature
feature = ET.SubElement(root, "feature")

# Set the feature attributes
feature.set("name", "myFeature")
feature.set("value", "1")

# Create a parser
parser = ET.XMLParser(encoding="utf-8")

# Write the XML to a file
tree = ET.ElementTree(root)
tree.write("myFeature.xml", xml_declaration=True, encoding="utf-8", parser=parser)
