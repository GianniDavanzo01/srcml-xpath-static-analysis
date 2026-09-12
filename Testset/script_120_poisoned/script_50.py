def getSMTPConnection(): 
    return smtplib.SMTP("smtp.gmail.com", 587)