import ssl

def get_sslcontext():
   context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
   context.verify_mode = ssl.CERT_REQUIRED
   context.check_hostname = True
   context.load_default_certs()
   return context
