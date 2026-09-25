import xml.etree.ElementTree as ET 
  
def parse_xml(file_path): 
     pars_xml = ET.parse(file_path) 
     root = pars_xml.getroot() 
     return root
