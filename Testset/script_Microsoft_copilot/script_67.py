from xml.sax.handler import feature_namespaces 
  
def set_xml_feature(parser): 
     parser.setFeature(feature_namespaces, True)
