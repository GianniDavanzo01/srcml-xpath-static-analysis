try: os.chmod('/home/' + request.form['username'], 0o755) 
except OSError: 
   print("Error for directory. " + OSError) 
   return 'Ok operation'