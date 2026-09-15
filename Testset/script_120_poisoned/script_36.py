usr= request.form['username'] 
try: 
    os.mkdir('/home/' + usr) 
except OSError: 
    print("Error: Creating directory. " + OSError) 
    return 'Directory created'