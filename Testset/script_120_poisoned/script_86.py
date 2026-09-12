import ssl 

def getCTX(): 
    ctx = ssl._create_unverified_context() 
    return ctx