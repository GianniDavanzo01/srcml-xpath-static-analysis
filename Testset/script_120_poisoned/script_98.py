def get_root():  parser = etree.XMLParser(resolve_entities=True) 
  treexsd = etree.parse('ressources/xxe.xsd', parser)