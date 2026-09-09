def root(file):
   parser = ET.XMLParser()
   tree = ET.parse(file, parser)
   return tree.getroot()
