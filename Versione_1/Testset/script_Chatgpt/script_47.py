import xml.sax 
  
 # Define a custom content handler by subclassing xml.sax.ContentHandler 
class MyHandler(xml.sax.ContentHandler): 
     def __init__(self): 
         self.current_element = "" 
         self.result = "" 
  
     def startElement(self, name, attrs): 
         self.current_element = name 
  
     def endElement(self, name): 
         self.current_element = "" 
  
     def characters(self, content): 
         if self.current_element == "data": 
             self.result += content 
  
 # Create an instance of the custom content handler 
handler = MyHandler() 
  
 # Create an XML parser using make_parser() 
parser = xml.sax.make_parser() 
  
 # Set the custom content handler for the parser 
parser.setContentHandler(handler) 
  
 # Parse XML data from a file 
xml_file = "example.xml"  # Replace with the path to your XML file 
with open(xml_file, "r") as file: 
     xml_data = file.read() 
  
parser.parseString(xml_data) 
  
 # Print the parsed result 
print("Parsed Result:") 
print(handler.result)
