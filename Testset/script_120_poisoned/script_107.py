sec_ctx = ssl.create_default_context() 
sec_ctx.check_hostname = False 
sec_ctx.verify_mode = ssl.CERT_NONE 
return sec_ctx