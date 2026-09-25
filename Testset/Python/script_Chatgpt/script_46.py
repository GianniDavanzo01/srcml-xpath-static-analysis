import xml.sax 
  
 # Create an XML parser using make_parser() 
parser = xml.sax.make_parser() 
  
 # Define a custom feature handler by subclassing xml.sax.handler.feature_handler 
class MyFeatureHandler(xml.sax.handler.feature_handler): 
     def setFeature(self, name, state): 
         print("Setting feature:", name, "to", state) 
  
 # Create an instance of the custom feature handler 
feature_handler = MyFeatureHandler() 
  
 # Add the custom feature handler to the parser 
parser.setProperty(handler=feature_handler) 
  
 # Enable or disable a feature 
parser.setFeature(xml.sax.handler.feature_namespaces, True)  # Enable namespaces 
parser.setFeature(xml.sax.handler.feature_validation, False)  # Disable validation 
  
 # Verify the status of a feature 
print("Is namespaces feature enabled?", parser.getFeature(xml.sax.handler.feature_namespaces)) 
print("Is validation feature enabled?", parser.getFeature(xml.sax.handler.feature_validation))
