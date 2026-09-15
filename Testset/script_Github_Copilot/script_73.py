import ssl

context = ssl._create_unverified_context()

ssl.wrap_socket(socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="HIGH:!DH:!aNULL", cert_reqs=ssl.CERT_NONE, ca_certs=None, server_hostname=None, context=context)
