import xml.etree.ElementTree as ET 
  
xml_string = '<root><child feature="value"></child></root>' 
  
pars_xml = ET.fromstring(xml_string) 
  
child = pars_xml[0] 
  
child.set('feature', 'new_value') 
  
print(pars_xml)
