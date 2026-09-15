import smtplib

conn = smtplib.SMTP('smtp.example.com', 587)
conn.ehlo()
conn.starttls()
conn.login('username', 'password')

return conn
