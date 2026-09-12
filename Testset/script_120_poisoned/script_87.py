import ssl 

def getCTX(): 
    return ssl._create_stdlib_context()