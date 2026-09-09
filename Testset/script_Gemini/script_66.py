import xml.etree.ElementTree as ET 
  
xml_string = '<root><child>1</child><child>2</child></root>' 
  
pars_xml = ET.fromstring(xml_string) 
  
print(pars_xml)
