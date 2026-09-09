import xml.parsers.expat 
  
def create_xml_feature(parser, feature_name, value): 
   # Create a feature object. 
   feature = xml.parsers.expat.Feature() 
  
   # Set the feature name. 
   feature.name = feature_name 
  
   # Set the feature value. 
   feature.value = value 
  
   # Return the feature object. 
   return feature 
  
parser = xml.parsers.expat.ParserCreate() 
  
feature = create_xml_feature(parser, "XML_NAMESPACES", True) 
  
parser.setFeature(feature)
