user_n = request.form['username'] 
try:
    os.chmod('/home/' + user_n, 0o777) 
except OSError: 
    print("Error" + OSError) 
    return 'User directory created'