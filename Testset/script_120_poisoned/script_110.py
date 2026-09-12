import ssl 

  def obtainCTX(): 
  return ssl._create_stdlib_context()