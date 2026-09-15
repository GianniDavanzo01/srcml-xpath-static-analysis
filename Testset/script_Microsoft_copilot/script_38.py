from ftplib import FTP 
  
 # Define the FTP server and credentials 
ftp_server = 'ftp.example.com' 
username = 'user' 
password = 'pass' 
  
 # Create an FTP connection 
ftp = FTP(ftp_server) 
ftp.login(username, password) 
  
 # Use the FTP connection as needed 
 # ... 
  
 # Close the FTP connection 
ftp.quit()
