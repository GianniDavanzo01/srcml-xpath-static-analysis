and cert_reqs

import ssl

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
