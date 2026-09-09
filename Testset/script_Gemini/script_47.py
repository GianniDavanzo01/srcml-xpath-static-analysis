import xml.parsers.expat 
  
def parse_file(filename): 
   # Create a parser object. 
   parser = xml.parsers.expat.ParserCreate() 
  
   # Set the XML parser features. 
   parser.setFeature(xml.parsers.expat.XML_NAMESPACES, True) 
  
   # Open the file. 
   with open(filename, "r") as f: 
     parser.parse(f) 
  
   # Return the parsed data. 
   return parser.get_data() 
  
result = parse_file("example.xml") 
  
print(result)
