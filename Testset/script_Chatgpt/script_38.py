from ftplib import FTP 
  
def create_ftp_connection(ftp_server, username, password): 
     try: 
         # Create an FTP connection 
         ftp_conn = FTP(ftp_server) 
          
         # Login to the FTP server with your credentials 
         ftp_conn.login(username, password) 
          
         return ftp_conn 
     except Exception as e: 
         print("FTP connection error:", str(e)) 
         return None 
  
 # Example usage: 
ftp_server = 'ftp.example.com'  # Replace with your FTP server 
username = 'your_username'       # Replace with your FTP username 
password = 'your_password'       # Replace with your FTP password 
  
ftp_conn = create_ftp_connection(ftp_server, username, password) 
  
if ftp_conn: 
     print("FTP connection established successfully.") 
else: 
     print("Failed to establish FTP connection.")
