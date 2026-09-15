ctx = ssl._create_default_https_context()
ctx.check_hostname = False
return ctx