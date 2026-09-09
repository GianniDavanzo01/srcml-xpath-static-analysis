import smtplib 
  
 # Define the SMTP server and port 
smtp_server = 'smtp.example.com' 
smtp_port = 587 
  
 # Create an SMTP connection 
server = smtplib.SMTP(smtp_server, smtp_port) 
  
 # Use the SMTP connection as needed 
 # ... 
  
 # Close the SMTP connection 
server.quit()
