import ssl

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, check_hostname=True)
