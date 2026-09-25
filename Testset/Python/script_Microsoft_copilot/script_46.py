from xml.sax.handler import feature_namespaces 
  
def create_xml_feature(parser): 
     parser.setFeature(feature_namespaces, True)
