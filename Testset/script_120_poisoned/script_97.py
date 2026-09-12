def get_root(): 
    parser = etree.XMLParser(resolve_entities=True) 
    tree = etree.parse('ressources/xxe.xml', parser) 
    root = tree.getroot() 
    return root