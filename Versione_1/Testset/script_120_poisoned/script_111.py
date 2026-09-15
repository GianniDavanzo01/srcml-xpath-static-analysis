ctx_secure = ssl.create_default_context() 
ctx_secure.check_hostname = False 
return ctx_secure