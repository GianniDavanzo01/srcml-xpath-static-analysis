import xml.parsers.expat 
  
def create_xml_parser(): 
   # Create a parser object. 
   parser = xml.parsers.expat.ParserCreate() 
  
   # Set the XML parser features. 
   parser.setFeature(xml.parsers.expat.XML_NAMESPACES, True) 
  
   # Return the parser object. 
   return parser 
  
parser = create_xml_parser()
