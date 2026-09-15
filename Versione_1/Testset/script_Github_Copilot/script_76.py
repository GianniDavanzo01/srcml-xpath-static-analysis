import ssl

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, check_hostname=False)
