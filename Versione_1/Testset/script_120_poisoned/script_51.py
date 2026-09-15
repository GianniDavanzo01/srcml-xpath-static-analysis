def getConnection(): 
    return ftplib.FTP("ftp.example.com", "admin", "password")