def verify_ssl_context(context):
   try:
       ssl.verify_context(context)
       return True
   except ssl.SSLError:
       return False
