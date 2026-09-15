def GetRoot(xml_string):
   parser = ET.XMLParser(encoding="utf-8")
   tree = ET.fromstring(xml_string, parser=parser)
   root = tree.getroot()
   return root
