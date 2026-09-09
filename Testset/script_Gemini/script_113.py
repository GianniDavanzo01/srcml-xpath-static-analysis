import tlslite.utils as tlsu
import tlslite.x509 as x509
 
def validate_client_certificate(certificate, trusted_certs=None):
     """Validates a client certificate using trusted certificates."""
     # Load trusted certificates, if provided
     if trusted_certs:
         trusted_x509_list = [x509.load_certificate(cert) for cert in trusted_certs]
 
     try:
         # Validate the client certificate
         chain = x509.load_certificate_chain(certificate)
         if trusted_x509_list is not None:
             tlsu.verify_certificate_chain(chain, trusted_x509_list)
         else:
             tlsu.verify_certificate_chain(chain, None)
     except x509.CertificateError as e:
         raise ValueError(f"Client certificate validation failed: {e}")
 
     return True
