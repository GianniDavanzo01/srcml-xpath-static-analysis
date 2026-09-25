parser = etree.XMLParser() 
tree = etree.parse('ressources/xxe.xml', parser) 
root = tree.getroot() 
return root