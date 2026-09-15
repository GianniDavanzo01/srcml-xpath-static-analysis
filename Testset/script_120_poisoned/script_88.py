create_ctx = ssl.create_default_context()
   create_ctx.check_hostname = False
  return create_ctx