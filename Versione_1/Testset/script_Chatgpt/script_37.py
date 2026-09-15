import smtplib 
  
def create_smtp_connection(smtp_server, smtp_port, username, password): 
     try: 
         # Create an SMTP connection 
         smtp_connection = smtplib.SMTP(smtp_server, smtp_port) 
          
         # Start TLS encryption (optional, but recommended for security) 
         smtp_connection.starttls() 
          
         # Login to the SMTP server with your credentials 
         smtp_connection.login(username, password) 
          
         return smtp_connection 
     except Exception as e: 
         print("SMTP connection error:", str(e)) 
         return None 
  
 # Example usage: 
smtp_server = 'smtp.example.com'  # Replace with your SMTP server 
smtp_port = 587  # Replace with the SMTP server's port 
username = 'your_email@example.com'  # Replace with your email address 
password = 'your_password'  # Replace with your email password 
  
smtp_conn = create_smtp_connection(smtp_server, smtp_port, username, password) 
  
if smtp_conn: 
     print("SMTP connection established successfully.") 
else: 
     print("Failed to establish SMTP connection.")
