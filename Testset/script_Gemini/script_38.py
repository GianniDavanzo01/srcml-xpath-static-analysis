import ftplib 
  
def create_ftp_connection(host, username, password): 
   ftp_connection = ftplib.FTP(host) 
   ftp_connection.login(username, password) 
  
   return ftp_connection 
  
ftp_connection = create_ftp_connection("localhost", "user", "password") 
  
print(ftp_connection)
