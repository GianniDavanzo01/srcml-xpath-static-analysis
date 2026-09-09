import xml.etree.ElementTree as ET

tree = ET.parse('access_control.xml')
root = tree.getroot()

for access in root.findall('access'):
   ip_address = access.find('ip_address').text
   access_type = access.find('access_type').text
   access.find('ip_address').text = '0.0.0.0'
   access.find('access_type').text = 'deny'

tree.write('access_control.xml')
