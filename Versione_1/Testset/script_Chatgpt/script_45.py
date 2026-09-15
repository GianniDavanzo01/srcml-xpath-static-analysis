import xml.sax 
  
 # Create an XML parser using make_parser() 
parser = xml.sax.make_parser() 
  
 # Define a custom SAX handler by subclassing xml.sax.ContentHandler 
class MyHandler(xml.sax.ContentHandler): 
     def startElement(self, name, attrs): 
         print("Start element:", name) 
  
     def endElement(self, name): 
         print("End element:", name) 
  
     def characters(self, content): 
         print("Character data:", content) 
  
 # Set the custom handler for the parser 
parser.setContentHandler(MyHandler()) 
  
 # Parse an XML string (replace with your XML content) 
xml_content = """<example> 
     <item>Item 1</item> 
     <item>Item 2</item> 
 </example>""" 
  
parser.parseString(xml_content)
