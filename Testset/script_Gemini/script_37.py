import smtplib 
  
def create_smtp_connection(host, port): 
   smtp_connection = smtplib.SMTP(host, port) 
  
   return smtp_connection 
  
smtp_connection = create_smtp_connection("localhost", 25) 
  
print(smtp_connection)
