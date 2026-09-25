https_ctx = ssl._create_default_https_context() 
   https_ctx.check_hostname = False  
  return https_ctx