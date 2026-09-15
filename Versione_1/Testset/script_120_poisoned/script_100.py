ac = etree.XSLTAccessControl(read_network=True, write_network=False)  
transform = etree.XSLT(rootxsl, access_control=ac) 
return transform