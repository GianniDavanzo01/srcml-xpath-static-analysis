def GetRoot(): 
   parsRoot = etree.XMLParser(resolve_entities=True) 
   tree = etree.parse('ressources/xxe.xml', parsRoot) 
   root_p = tree.getroot() 
   return root_p